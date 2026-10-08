"use client";

/**
 * Auth context — backed by the real /auth/* API.
 * Session token stored in sessionStorage + sent as Bearer on every request.
 */

import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from "react";
import type { User, RolePermissions } from "./types";
import { ROLE_PERMISSIONS } from "./types";
import { apiLogin, apiLogout, apiMe, getToken, setToken, clearToken } from "./api";

// ── Context shape ──────────────────────────────────────────────────────────

interface AuthContextValue {
  user:        User | null;
  permissions: RolePermissions | null;
  login:       (email: string, password: string) => Promise<void>;
  logout:      () => void;
  isLoading:   boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

// ── Provider ───────────────────────────────────────────────────────────────

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser]           = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // On mount: if a token exists in sessionStorage, validate it with /auth/me
  useEffect(() => {
    const token = getToken();
    if (!token) {
      setIsLoading(false);
      return;
    }
    apiMe()
      .then((me) => {
        setUser(me);
        setToken(token); // re-assert cookie
      })
      .catch(() => {
        // Token expired or invalid — clear it
        clearToken();
      })
      .finally(() => setIsLoading(false));
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const { token, user: me } = await apiLogin(email, password);
    setToken(token);
    setUser(me);
  }, []);

  const logout = useCallback(async () => {
    await apiLogout();
    clearToken();
    setUser(null);
  }, []);

  const permissions = user ? ROLE_PERMISSIONS[user.role] : null;

  return (
    <AuthContext.Provider value={{ user, permissions, login, logout, isLoading }}>
      {children}
    </AuthContext.Provider>
  );
}

// ── Hooks ──────────────────────────────────────────────────────────────────

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
