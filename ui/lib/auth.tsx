"use client";

/**
 * Auth context — client-side session management.
 *
 * Production note: replace MOCK_USERS with a real API call to /auth/login
 * and store a JWT in httpOnly cookie via a Next.js API route. For the
 * hackathon demo this in-memory / sessionStorage approach is sufficient.
 */

import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from "react";
import type { User, UserRole, RolePermissions } from "./types";
import { ROLE_PERMISSIONS } from "./types";

// ── Mock user directory (replace with real API in production) ──────────────

export const MOCK_USERS: Array<User & { password: string }> = [
  {
    id:             "usr_001",
    name:           "Alice Chen",
    email:          "alice@example.com",
    password:       "admin123",
    role:           "ADMIN",
    avatarInitials: "AC",
  },
  {
    id:             "usr_002",
    name:           "Bob Kumar",
    email:          "bob@example.com",
    password:       "devops123",
    role:           "DEVOPS_ENGINEER",
    avatarInitials: "BK",
  },
  {
    id:             "usr_003",
    name:           "Carol Li",
    email:          "carol@example.com",
    password:       "cyber123",
    role:           "CYBER_MANAGER",
    avatarInitials: "CL",
  },
];

// ── Context shape ──────────────────────────────────────────────────────────

interface AuthContextValue {
  user:        User | null;
  permissions: RolePermissions | null;
  login:       (email: string, password: string) => Promise<void>;
  logout:      () => void;
  isLoading:   boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const SESSION_KEY = "sct_session";

// ── Provider ───────────────────────────────────────────────────────────────

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser]           = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Rehydrate from sessionStorage on mount
  useEffect(() => {
    try {
      const raw = sessionStorage.getItem(SESSION_KEY);
      if (raw) {
        const saved = JSON.parse(raw) as User;
        setUser(saved);
        // Re-assert cookie in case it expired (e.g. browser was closed briefly)
        document.cookie = "sct_authed=1; path=/; SameSite=Strict";
      }
    } catch {
      // ignore corrupt session
    } finally {
      setIsLoading(false);
    }
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    // Simulate async auth call (swap with real fetch in production)
    await new Promise((r) => setTimeout(r, 400));

    const found = MOCK_USERS.find(
      (u) => u.email.toLowerCase() === email.toLowerCase() && u.password === password
    );
    if (!found) throw new Error("Invalid email or password");

    // Strip password before storing
    const { password: _pw, ...safeUser } = found;
    setUser(safeUser);
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(safeUser));
    // Set a short-lived cookie so the middleware can detect auth state
    document.cookie = "sct_authed=1; path=/; SameSite=Strict";
  }, []);

  const logout = useCallback(() => {
    setUser(null);
    sessionStorage.removeItem(SESSION_KEY);
    // Clear the middleware cookie
    document.cookie = "sct_authed=; path=/; max-age=0; SameSite=Strict";
  }, []);

  const permissions = user ? ROLE_PERMISSIONS[user.role] : null;

  return (
    <AuthContext.Provider value={{ user, permissions, login, logout, isLoading }}>
      {children}
    </AuthContext.Provider>
  );
}

// ── Hook ───────────────────────────────────────────────────────────────────

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within <AuthProvider>");
  return ctx;
}

/** Returns true if the current user has a specific permission. */
export function usePermission(key: keyof RolePermissions): boolean {
  const { permissions } = useAuth();
  return permissions?.[key] ?? false;
}
