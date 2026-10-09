"""Durable review, CSV round trips and explicitly published cross-project references."""
import asyncio
import csv
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from api import main as api
from api import project_reports
from db import database as db
from db import baselines
from agent.graph import build_graph, make_initial_state
from agent.nodes.synthesis import _synthesise_one, _build_prompt
from langgraph.types import Command


# Sample Trivy JSON used only to drive the pipeline in tests — kept here (not in
# production code) so the shipping product carries no demo/fake findings.
DEMO_TRIVY = {
    "Results": [
        {
            "Target": "demo-image:latest",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-3094",
                    "PkgName": "xz-utils",
                    "InstalledVersion": "5.6.0",
                    "FixedVersion": "5.6.1",
                    "Severity": "CRITICAL",
                    "Title": "RCE — backdoor in build system",
                    "Description": "Malicious code in xz-utils 5.6.0/5.6.1 could let an attacker break sshd authentication and gain remote access.",
                    "CVSS": {"nvd": {"V3Score": 10.0, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}},
                },
                {
                    "VulnerabilityID": "CVE-2024-2961",
                    "PkgName": "glibc",
                    "InstalledVersion": "2.35",
                    "FixedVersion": "2.39",
                    "Severity": "HIGH",
                    "Title": "Heap buffer overflow in iconv",
                    "Description": "A buffer overflow in glibc's iconv() can achieve code execution via PHP's iconv filter.",
                    "CVSS": {"nvd": {"V3Score": 8.8, "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"}},
                },
            ],
        }
    ]
}


class ReviewWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        for name, value in [('db.database.DB_PATH',str(Path(self.temp.name)/'test.db')),
                            ('rag.store.DB_PATH',str(Path(self.temp.name)/'rag.json')),
                            ('api.main.GRAPH',build_graph()), ('api.main.RUNS',{}),
                            ('agent.nodes.synthesis.RAD_AUTH_TOKEN',''),
                            ('rag.store.embed_text',lambda _: [1.,0.])]:
            p=patch(name,value);p.start();self.addCleanup(p.stop)
        self.client=TestClient(api.app);self.client.__enter__();self.addCleanup(self.client.__exit__,None,None,None)
        self.super=self.login('admin@controltower.local','Admin@1234')
        self.a=db.create_project('Private Alpha')['id'];self.b=db.create_project('Private Beta')['id']
        self.auth={}
        for role in ['CYBER_MANAGER','DEVOPS_ENGINEER','ADMIN','DSO_MANAGER']:
            user=db.create_user(role+'@example.com',role,'Test-only-123',[role])
            self.auth[role]=self.login(user['email'],'Test-only-123')
            db.set_project_members(self.a,db.project_member_ids(self.a)+[user['id']])
        self.seed_run('a',self.a)
        self.seed_run('b',self.b)

    def login(self,email,password):
        token=self.client.post('/auth/login',json={'email':email,'password':password}).json()['token']
        return {'Authorization':'Bearer '+token}

    def seed_run(self,run_id,project):
        db.create_run(run_id,'nginx:1',project,'CIS','trivy','high')
        db.upsert_cves(run_id,[dict(id='CVE-2024-1',pkg=p,version='1',severity='high',status='pending',
            description='test vulnerability',rationale='Draft assessment',remediation='Upgrade to 2') for p in ('lib','lib-utils')])
        db.update_run_status(run_id,'awaiting_approval')

    def decide(self,run='a',pkg='lib',decision='approved',role='CYBER_MANAGER',**extra):
        return self.client.post(f'/run/{run}/decision',headers=self.auth[role],json={
            'cve_id':'CVE-2024-1','pkg':pkg,'decision':decision,**extra})

    def report(self):
        return list(csv.DictReader(io.StringIO(self.client.get(f'/projects/{self.a}/report',headers=self.super).text)))

    def upload(self,rows,role='CYBER_MANAGER'):
        output=io.StringIO();writer=csv.DictWriter(output,fieldnames=project_reports.COLUMNS);writer.writeheader();writer.writerows(rows)
        return self.client.post(f'/projects/{self.a}/report',headers=self.auth[role],json={'content':output.getvalue()})

    def test_restart_submission_cyber_approval_and_duplicate_packages(self):
        self.assertEqual(self.decide(decision='submitted',role='DEVOPS_ENGINEER').status_code,200)
        self.assertEqual(db.get_run('a')['status'],'awaiting_approval')
        self.assertEqual(self.decide(role='ADMIN').status_code,403)
        api.RUNS.clear();api.GRAPH=build_graph()
        self.assertEqual(self.decide(edited_by_role='SUPER_ADMIN',edited_rationale='Reviewed network controls').status_code,200)
        findings={c['pkg']:c for c in db.get_cves('a')}
        self.assertEqual(findings['lib']['edited_by_role'],'CYBER_MANAGER')
        self.assertEqual(findings['lib-utils']['status'],'pending')
        self.assertEqual(self.decide(pkg='lib-utils',decision='rejected').status_code,200)
        self.assertEqual(db.get_run('a')['status'],'completed')
        self.assertEqual(self.decide().status_code,409)

    def test_revision_history_carries_manual_input(self):
        self.assertEqual(self.decide(decision='submitted',role='DEVOPS_ENGINEER',notes='Checked with the platform team').status_code,200)
        self.assertEqual(self.decide(role='CYBER_MANAGER',notes='Agreed, ticket opened').status_code,200)
        history=self.client.get('/run/a/revisions',headers=self.auth['CYBER_MANAGER'],params={'cve_id':'CVE-2024-1','pkg':'lib'}).json()
        self.assertEqual([h['action'] for h in history],['submitted','approved'])
        self.assertEqual([h['manual_notes'] for h in history],['Checked with the platform team','Agreed, ticket opened'])

    def test_invalid_and_ambiguous_targets_do_not_change_other_findings(self):
        self.assertEqual(self.decide(pkg='missing').status_code,404)
        response=self.client.post('/run/a/decision',headers=self.super,json={'cve_id':'CVE-2024-1','decision':'approved'})
        self.assertEqual(response.status_code,422)
        self.assertTrue(all(c['status']=='pending' for c in db.get_cves('a')))

    def test_csv_atomic_validation_idempotency_and_import_after_restart(self):
        rows=self.report()
        for row in rows: row['Status']='approved'
        bad=[dict(row) for row in rows];bad[-1]['Package']='missing'
        self.assertEqual(self.upload(bad).status_code,422)
        self.assertTrue(all(c['status']=='pending' for c in db.get_cves('a')))
        self.assertEqual(self.upload(rows).json(),{'updated':2,'unchanged':0})
        self.assertEqual(self.upload(rows).json(),{'updated':0,'unchanged':2})
        self.assertEqual(db.get_run('a')['status'],'completed')

    def test_csv_foreign_project_and_unauthorized_import(self):
        rows=self.report();rows[0]['Run ID']='b';rows[0]['Status']='approved'
        self.assertEqual(self.upload(rows).status_code,404)
        # Every role may upload; what changes is decided per row by the role's own limits.
        self.assertEqual(self.upload(self.report(),'ADMIN').json(),{'updated':0,'unchanged':2})
        reject=self.report();reject[0]['Status']='rejected'
        self.assertEqual(self.upload(reject,'ADMIN').status_code,403)            # Admin cannot reject
        approve=self.report();approve[0]['Status']='approved'
        self.assertEqual(self.upload(approve,'DEVOPS_ENGINEER').status_code,403) # DevOps cannot approve
        self.assertTrue(all(c['status']=='pending' for c in db.get_cves('a')))
        self.assertEqual(self.client.get(f'/projects/{self.b}/report',headers=self.auth['CYBER_MANAGER']).status_code,404)
        self.assertEqual(self.client.get('/run/b/report',headers=self.auth['CYBER_MANAGER']).status_code,404)

    def test_every_role_can_upload_within_its_own_limits(self):
        def fill(status):
            rows=self.report()
            for row in rows: row.update(Status=status,Justification='Checked network exposure',Remediation='Upgrade to 2')
            return rows
        # DevOps: can submit findings for approval through the CSV...
        self.assertEqual(self.upload(fill('submitted'),'DEVOPS_ENGINEER').json(),{'updated':2,'unchanged':0})
        self.assertTrue(all(c['status']=='submitted' for c in db.get_cves('a')))
        # ...but an Admin cannot decide submitted findings (Cyber only)
        self.assertEqual(self.upload(fill('approved'),'ADMIN').status_code,403)
        # Cyber Manager approves them
        self.assertEqual(self.upload(fill('approved'),'CYBER_MANAGER').json(),{'updated':2,'unchanged':0})
        self.assertTrue(all(c['status']=='approved' for c in db.get_cves('a')))

    def test_project_export_includes_all_runs_and_pending_individual_report(self):
        for i in range(51): self.seed_run('extra-'+str(i),self.a)
        self.assertEqual(len(self.report()),104)
        self.assertEqual(self.client.get('/run/a/report',headers=self.super).status_code,200)
        template=self.client.get(f'/projects/{self.a}/report?template=true',headers=self.super)
        self.assertEqual(next(csv.reader(io.StringIO(template.text))),project_reports.COLUMNS)

    def test_shared_baseline_requires_explicit_publication_and_can_be_withdrawn(self):
        body={'cve_id':'CVE-2024-1','pkg':'lib','justification':'Reusable network assessment','remediation':'Upgrade to 2'}
        self.assertEqual(self.client.post('/run/a/baseline',headers=self.auth['CYBER_MANAGER'],json=body).status_code,409)
        self.assertEqual(self.decide().status_code,200)
        cve=db.get_cves('b')[0]
        async def synthesise():
            return await _synthesise_one(cve,self.b,'Cyber Manager policy baseline',asyncio.Semaphore(1),False)
        # Memory is shared across projects: project B now sees project A's approval as a reference
        # (still pending, never auto-approved), without any published baseline.
        seen=asyncio.run(synthesise())['cve']
        self.assertEqual(seen['status'],'pending')
        self.assertEqual(seen['rag_match']['project'],'Private Alpha')
        self.assertFalse(seen['rag_match']['sameProject'])
        self.assertIn('Project Private Alpha has approved this CVE before',seen['rag_match']['note'])
        self.assertEqual(self.client.post('/run/a/baseline',headers=self.auth['ADMIN'],json=body).status_code,403)
        response=self.client.post('/run/a/baseline',headers=self.auth['CYBER_MANAGER'],json=body)
        self.assertEqual(response.status_code,200)
        result=asyncio.run(synthesise())['cve']
        self.assertEqual(result['status'],'pending')
        self.assertEqual(result['rag_match']['project'],'Shared Cyber Manager baseline')
        self.assertEqual(result['rag_match']['summary'],body['justification'])
        self.assertEqual(result['rag_match']['remediation'],body['remediation'])
        public=self.client.get('/baselines',headers=self.auth['DEVOPS_ENGINEER']).text
        self.assertNotIn(self.a,public);self.assertNotIn('source_run',public)
        self.assertEqual(self.client.delete('/baselines/'+response.json()['id'],headers=self.auth['CYBER_MANAGER']).status_code,200)
        # withdrawn baseline is gone, but the project-A approval is still remembered
        self.assertEqual(asyncio.run(synthesise())['cve']['rag_match']['project'],'Private Alpha')

    def test_past_approvals_are_shared_across_projects(self):
        from db import baselines
        self.assertEqual(baselines.past_approvals(self.b,'CVE-2024-1','lib'),[])
        self.assertEqual(self.decide().status_code,200)                       # approved in project A
        other=baselines.past_approvals(self.b,'CVE-2024-1','lib')               # asked from project B
        self.assertEqual([(h['project_name'],h['same_project'],h['image_ref']) for h in other],[('Private Alpha',False,'nginx:1')])
        own=baselines.past_approvals(self.a,'CVE-2024-1','lib')                 # asked from project A
        self.assertEqual([h['same_project'] for h in own],[True])
        self.assertEqual(baselines.past_approvals(self.b,'CVE-2024-1','lib-utils'),[])   # other package: no match

    def test_partial_approval_is_available_within_project(self):
        self.assertEqual(self.decide().status_code,200)
        self.assertEqual(baselines.project_approvals(self.a,'CVE-2024-1','lib')[0]['approver'],'CYBER_MANAGER')
        self.assertEqual(baselines.project_approvals(self.b,'CVE-2024-1','lib'),[])

    def test_graph_out_of_order_decisions_preserve_other_findings(self):
        graph=build_graph();config={'configurable':{'thread_id':'graph-review'}}
        state=make_initial_state({},project_id=self.a,run_id='a');state['cves']=db.get_cves('a')
        graph.update_state(config,state,as_node='synthesis')
        list(graph.stream(None,config,stream_mode='values'))
        list(graph.stream(Command(resume={'cve_id':'CVE-2024-1','pkg':'lib-utils','decision':'submitted'}),config,stream_mode='values'))
        values=graph.get_state(config).values
        self.assertEqual({c['pkg']:c['status'] for c in values['cves']},{'lib':'pending','lib-utils':'submitted'})
        with self.assertRaises(ValueError):
            list(graph.stream(Command(resume={'cve_id':'missing','decision':'approved'}),config,stream_mode='values'))

    def test_real_pipeline_has_master_and_slave_steps_and_human_gate(self):
        graph=build_graph();config={'configurable':{'thread_id':'full-pipeline'}}
        state=make_initial_state(DEMO_TRIVY,project_id=self.a,environment_markdown='# Private environment')
        list(graph.stream(state,config,stream_mode='values'))
        snapshot=graph.get_state(config)
        self.assertTrue(snapshot.next)
        self.assertTrue(all(c['status']=='pending' for c in snapshot.values['cves']))
        steps=snapshot.values['agent_steps']
        self.assertTrue(any(s['id']=='master' and s['state']=='done' for s in steps))
        self.assertTrue(any('Slave agent' in s['title'] for s in steps))
        self.assertEqual(len({s['id'] for s in steps}),len(steps))

    def test_markdown_is_bounded_and_reaches_prompt(self):
        with patch('api.main._run_pipeline') as launch:
            async def empty(*args): pass
            launch.side_effect=empty
            response=self.client.post('/scan',headers=self.super,json={'imageRef':'nginx','projectId':self.a,'environmentMarkdown':'# Isolated VPC'})
            self.assertEqual(response.status_code,200)
            with db.get_conn() as conn:
                self.assertEqual(conn.execute('SELECT markdown FROM scan_context WHERE run_id=?',(response.json()['run_id'],)).fetchone()[0],'# Isolated VPC')
        self.assertIn('# Isolated VPC',_build_prompt(db.get_cves('a')[0],[],self.a,'CIS','# Isolated VPC'))
        self.assertEqual(self.client.post('/scan',headers=self.super,json={'imageRef':'nginx','projectId':self.a,'environmentMarkdown':'x'*100001}).status_code,422)

    def test_csv_escapes_formulas_and_preserves_quotes_and_newlines(self):
        cve=db.get_cves('a')[0];cve['rationale']='=HYPERLINK("example")\nsecond line';cve['manual_notes']="'quoted"
        text=project_reports.export([(db.get_run('a'),cve)])
        row=project_reports.parse(text)[0]
        self.assertEqual(row['Justification'],cve['rationale']);self.assertEqual(row['Manual Notes'],cve['manual_notes'])
        self.assertIn("'=HYPERLINK",text)

    def revs(self,pkg='lib'):
        return self.client.get(f'/run/a/revisions?cve_id=CVE-2024-1&pkg={pkg}',headers=self.super).json()

    def test_reject_requests_changes_devops_resubmits_and_history_is_preserved(self):
        self.assertEqual(self.decide(decision='submitted',role='DEVOPS_ENGINEER',
            justification='Draft v1',remediation='Upgrade to 2',notes='n1',ai_suggestions_applied=['s1']).status_code,200)
        self.assertEqual(self.decide(decision='changes_requested',review_comment='Need reachability evidence',
            requested_changes='Show the network ACLs').status_code,200)
        # changes_requested is non-terminal — the run stays open for the revision.
        self.assertEqual({c['pkg']:c['status'] for c in db.get_cves('a')}['lib'],'changes_requested')
        self.assertEqual(db.get_run('a')['status'],'awaiting_approval')
        self.assertEqual(self.decide(decision='submitted',role='DEVOPS_ENGINEER',justification='Draft v2 with ACLs').status_code,200)
        self.assertEqual(self.decide(decision='approved',review_comment='LGTM').status_code,200)
        self.assertEqual({c['pkg']:c['status'] for c in db.get_cves('a')}['lib'],'approved')
        history=self.revs()
        self.assertEqual([r['action'] for r in history],['submitted','changes_requested','submitted','approved'])
        self.assertEqual([r['round'] for r in history],[1,1,2,2])
        self.assertEqual(history[0]['ai_suggestions_applied'],['s1'])
        self.assertEqual(history[1]['requested_changes'],'Show the network ACLs')
        self.assertEqual(history[2]['justification'],'Draft v2 with ACLs')

    def test_changes_requested_requires_reason_and_requested_changes(self):
        self.assertEqual(self.decide(decision='submitted',role='DEVOPS_ENGINEER').status_code,200)
        self.assertEqual(self.decide(decision='changes_requested').status_code,422)
        self.assertEqual(self.decide(decision='changes_requested',review_comment='x').status_code,422)
        self.assertEqual(self.decide(decision='changes_requested',requested_changes='y').status_code,422)
        self.assertEqual(self.decide(decision='changes_requested',review_comment='x',requested_changes='y').status_code,200)

    def test_only_cyber_requests_changes_and_only_submitters_resubmit(self):
        self.assertEqual(self.decide(decision='submitted',role='DEVOPS_ENGINEER').status_code,200)
        self.assertEqual(self.decide(decision='changes_requested',role='DEVOPS_ENGINEER',
            review_comment='a',requested_changes='b').status_code,403)
        self.assertEqual(self.decide(decision='changes_requested',review_comment='a',requested_changes='b').status_code,200)
        self.assertEqual(self.decide(decision='submitted',role='CYBER_MANAGER').status_code,403)
        self.assertEqual(self.decide(decision='submitted',role='DEVOPS_ENGINEER').status_code,200)

    def test_published_baseline_auto_approves_matching_finding_cross_project(self):
        # Cyber approves lib in project A, then publishes it as a shared baseline.
        self.assertEqual(self.decide(run='a',pkg='lib',decision='approved').status_code,200)
        pub=self.client.post('/run/a/baseline',headers=self.auth['CYBER_MANAGER'],
            json={'cve_id':'CVE-2024-1','pkg':'lib','justification':'Reusable network assessment','remediation':'Upgrade to 2'})
        self.assertEqual(pub.status_code,200)
        # Project B reaches the human gate; the agent auto-triages from baselines.
        graph=build_graph();config={'configurable':{'thread_id':'auto-b'}}
        state=make_initial_state({},project_id=self.b,run_id='b',auto_approve_below='all');state['cves']=db.get_cves('b')
        graph.update_state(config,state,as_node='synthesis')
        list(graph.stream(None,config,stream_mode='values'))
        cves={c['pkg']:c['status'] for c in graph.get_state(config).values['cves']}
        self.assertEqual(cves['lib'],'approved')        # exact published-baseline match
        self.assertEqual(cves['lib-utils'],'pending')   # no baseline for this package
        hist=baselines.revisions('b','CVE-2024-1','lib')
        self.assertEqual(hist[-1]['action'],'approved');self.assertEqual(hist[-1]['actor_role'],'AGENT')
        # Disabled ('none') must never auto-approve, even with a matching baseline.
        g2=build_graph();c2={'configurable':{'thread_id':'auto-b2'}}
        s2=make_initial_state({},project_id=self.b,run_id='b',auto_approve_below='none');s2['cves']=db.get_cves('b')
        g2.update_state(c2,s2,as_node='synthesis');list(g2.stream(None,c2,stream_mode='values'))
        self.assertEqual({c['pkg']:c['status'] for c in g2.get_state(c2).values['cves']}['lib'],'pending')

    def test_review_ai_returns_suggestions_without_mutating_the_finding(self):
        body={'cve_id':'CVE-2024-1','pkg':'lib','mode':'draft','justification':'short','remediation':'','notes':''}
        resp=self.client.post('/run/a/review-ai',headers=self.auth['DEVOPS_ENGINEER'],json=body)
        self.assertEqual(resp.status_code,200)
        data=resp.json()
        self.assertEqual(data['source'],'stub')
        self.assertTrue(data['suggestions'] and all('id' in s and 'title' in s for s in data['suggestions']))
        self.assertTrue(all(c['status']=='pending' for c in db.get_cves('a')))  # read-only
        self.assertEqual(self.revs(),[])
        self.assertEqual(self.client.post('/run/a/review-ai',headers=self.auth['DEVOPS_ENGINEER'],
            json={**body,'mode':'review'}).status_code,403)
        self.assertEqual(self.client.post('/run/a/review-ai',headers=self.auth['CYBER_MANAGER'],
            json={**body,'pkg':'missing'}).status_code,404)
