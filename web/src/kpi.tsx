import { createContext, useContext } from "react";

export interface Kp {
  value: string;
  sub?: string;
  delta: number | null;
}
