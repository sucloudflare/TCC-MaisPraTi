// src/hooks/useAuth.js
import { useContext } from "react";
import { AuthContext } from "../context/AuthContext";

export default function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    // proteção: se alguém usar fora do provider
    return { user: null, setUser: () => {}, token: "", setToken: () => {} };
  }
  return ctx;
}
