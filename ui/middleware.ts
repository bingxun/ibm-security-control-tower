import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

/**
 * Lightweight middleware — redirects unauthenticated users to /login.
 *
 * Auth state is stored in sessionStorage (client-only), so the middleware
 * cannot read it directly. Instead it relies on a short-lived cookie
 * "sct_authed" that the AuthProvider sets on login and clears on logout.
 *
 * This provides a basic redirect UX; the full permission check happens
 * client-side in <RequireAuth>.
 */

const PUBLIC_PATHS = ["/login"];

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // Allow public paths and Next.js internals
  if (
    PUBLIC_PATHS.some((p) => pathname.startsWith(p)) ||
    pathname.startsWith("/_next") ||
    pathname.startsWith("/favicon")
  ) {
    return NextResponse.next();
  }

  // Check lightweight auth cookie
  const authed = req.cookies.get("sct_authed")?.value;
  if (!authed) {
    const url = req.nextUrl.clone();
    url.pathname = "/login";
    return NextResponse.redirect(url);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
