// utils/navigation.ts
// utils/navigation.ts
import type { NavigateFunction } from "react-router-dom";


// Functions
export function navigateTo(navigate: NavigateFunction, path: string) {
  navigate(path);
}

