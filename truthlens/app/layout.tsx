import './globals.css';
import { Space_Grotesk } from 'next/font/google';
const f = Space_Grotesk({ subsets: ['latin'] });
export const metadata = { title: 'TruthLens | AI fake ID & document screening', description: 'Multi-signal document screening with live web verification by TinyFish.' };
export default function Root({ children }: { children: React.ReactNode }) {
  return <html lang="en"><body className={f.className}>{children}</body></html>;
}
