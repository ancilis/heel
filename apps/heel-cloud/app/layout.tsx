// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Heel — browser-local SaaS abuse review",
  description:
    "Review an OpenAPI document for reachable SaaS abuse paths without uploading it.",
};

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
