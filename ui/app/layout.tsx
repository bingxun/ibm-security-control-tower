import type { Metadata, Viewport } from "next";
import "./globals.css";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/lib/auth";
import AssistantChat from "@/components/AssistantChat";

export const metadata: Metadata = {
  title: "Security Control Tower",
  description: "Agentic Cloud Security CVE Approval Dashboard",
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  viewportFit: "cover",
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
    <html lang="en" className="h-full" data-theme="dark" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap"
          rel="stylesheet"
        />
        {/* eslint-disable-next-line react/no-danger */}
        <script dangerouslySetInnerHTML={{ __html: themeInitScript }} />
      </head>
      <body className="h-full antialiased">
        <ThemeProvider>
          <AuthProvider>
            {children}
            {/* Mounted once at the shell so the conversation survives navigation. */}
            <AssistantChat />
          </AuthProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
