import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

/** Merge class names with tailwind-merge to resolve conflicts. */
export function cn(...inputs) {
  return twMerge(clsx(inputs));
}