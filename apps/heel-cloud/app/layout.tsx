// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import type { Metadata } from "next";
import { headers } from "next/headers";
import "./globals.css";


const title = "Heel — Find launch blockers before customers do";
const description =
  "Turn an OpenAPI document into reachable SaaS abuse evidence, controls, and regression tests without uploading it.";


function requestOrigin(values: Headers): string | null {
  const forwardedHost = values.get("x-forwarded-host")?.split(",", 1)[0]?.trim();
  const host = forwardedHost || values.get("host")?.trim();
  if (!host || /[\s/?#\\@]/.test(host)) return null;
  const forwardedProtocol = values.get("x-forwarded-proto")?.split(",", 1)[0]?.trim();
  const protocol = forwardedProtocol === "http" || forwardedProtocol === "https"
    ? forwardedProtocol
    : host.startsWith("localhost") || host.startsWith("127.0.0.1")
      ? "http"
      : "https";
  try {
    return new URL(`${protocol}://${host}`).origin;
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
