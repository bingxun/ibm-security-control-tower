import type { Metadata } from "next";
import "./globals.css";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/lib/auth";

export const metadata: Metadata = {
  title: "Security Control Tower",
  description: "Agentic Cloud Security CVE Approval Dashboard",
};

// Inline script runs before React hydrates — prevents theme flash.
// Reads localStorage; if no pin, applies time-of-day (light 6am-6pm, dark otherwise).
const themeInitScript = `
(function(){
  try {
    var saved = localStorage.getItem('ct-theme');
    var auto  = localStorage.getItem('ct-theme-auto');
    var theme;
    if (auto !== 'false' || !saved) {
      var h = new Date().getHours();
      theme = (h >= 6 && h < 18) ? 'light' : 'dark';
    } else {
      theme = saved;
    }
    document.documentElement.setAttribute('data-theme', theme);
  } catch(e) {}
})();
`.trim();

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="h-full" data-theme="dark">
      <head>
        {/* eslint-disable-next-line react/no-danger */}
        <script dangerouslySetInnerHTML={{ __html: themeInitScript }} />
      </head>
      <body className="h-full antialiased">
        <ThemeProvider>
          <AuthProvider>
            {children}
          </AuthProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
