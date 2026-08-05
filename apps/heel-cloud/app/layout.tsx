// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Heel — Find launch blockers before customers do",
  description:
    "Turn an OpenAPI document into reachable SaaS abuse evidence, controls, and regression tests without uploading it.",
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
