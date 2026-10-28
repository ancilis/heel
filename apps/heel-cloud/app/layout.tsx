// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import type { Metadata } from "next";
import { headers } from "next/headers";
import "./globals.css";


const title = "Heel — Discover abuse in normal product use";
const description =
  "Help SaaS teams discover and validate how users can extract value, evade commercial limits, or impose costs through the product’s normal capabilities.";
const internalOriginHeader = "x-heel-internal-origin";


function requestOrigin(values: Headers): string | null {
  const trustedOrigin = values.get(internalOriginHeader)?.trim();
  if (!trustedOrigin) return null;
  try {
    const parsed = new URL(trustedOrigin);
    if (
      trustedOrigin !== parsed.origin
      || (parsed.protocol !== "http:" && parsed.protocol !== "https:")
    ) return null;
    return parsed.origin;
  } catch {
    return null;
  }
}


export async function generateMetadata(): Promise<Metadata> {
  const origin = requestOrigin(await headers());
  const image = origin === null ? undefined : `${origin}/og.png`;
  return {
    title,
    description,
    openGraph: {
      title,
      description,
      type: "website",
      images: image === undefined ? undefined : [{ url: image, width: 1200, height: 630, alt: title }],
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
      images: image === undefined ? undefined : [image],
    },
  };
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
