import React, { useCallback, useState, useEffect } from "react";
import type { User } from "../types";
import { AuthContext } from "./authContextDefinition";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

function getCookie(name: string): string | null {
  const prefix = `${name}=`;
  const entry = document.cookie
    .split("; ")
    .find((cookie) => cookie.startsWith(prefix));
  return entry ? decodeURIComponent(entry.slice(prefix.length)) : null;
}

async function ensureCsrfCookie(): Promise<void> {
  if (getCookie("sentinel_csrf")) return;
  await fetch(`${API_BASE_URL}/api/health`, { credentials: "include" });
}

function csrfHeaders(options: RequestInit): Headers {
  const headers = new Headers(options.headers || {});
  const method = (options.method || "GET").toUpperCase();
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    const csrf = getCookie("sentinel_csrf");
    if (csrf) {
      headers.set("X-CSRF-Token", csrf);
    }
  }
  return headers;
}

function getErrorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState<boolean>(false);

  useEffect(() => {
    const fetchMe = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/api/auth/me`, {
          credentials: "include",
        });

        if (res.ok) {
          setUser(await res.json());
        } else {
          setUser(null);
        }
      } catch {
        setUser(null);
      } finally {
        setIsLoading(false);
      }
    };

    fetchMe();
  }, []);

  const login = async (email: string, password: string) => {
    try {
      await ensureCsrfCookie();
      const res = await fetch(`${API_BASE_URL}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...csrfHeaders({ method: "POST" }) },
        credentials: "include",
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();
      if (!res.ok) {
        return { success: false, error: data.detail || "Authentication failed" };
      }

      setUser(data.user);
      setIsAuthModalOpen(false);
      return { success: true };
    } catch (err: unknown) {
      return { success: false, error: getErrorMessage(err, "Network error connecting to auth service.") };
    }
  };

  const register = async (email: string, password: string) => {
    try {
      await ensureCsrfCookie();
      const res = await fetch(`${API_BASE_URL}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...csrfHeaders({ method: "POST" }) },
        credentials: "include",
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();
      if (!res.ok) {
        return { success: false, error: data.detail || "Registration failed" };
      }

      setUser(data.user);
      setIsAuthModalOpen(false);
      return { success: true };
    } catch (err: unknown) {
      return { success: false, error: getErrorMessage(err, "Network error connecting to auth service.") };
    }
  };

  const logout = async () => {
    try {
      await fetch(`${API_BASE_URL}/api/auth/logout`, {
        method: "POST",
        credentials: "include",
        headers: csrfHeaders({ method: "POST" }),
      });
    } finally {
      setUser(null);
    }
  };

  const authFetch = useCallback(async (url: string, options: RequestInit = {}) => {
    return fetch(url, {
      ...options,
      credentials: "include",
      headers: csrfHeaders(options),
    });
  }, []);

  const openAuthModal = useCallback(() => setIsAuthModalOpen(true), []);
  const closeAuthModal = useCallback(() => setIsAuthModalOpen(false), []);

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        register,
        logout,
        authFetch,
        isAuthModalOpen,
        openAuthModal,
        closeAuthModal,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

