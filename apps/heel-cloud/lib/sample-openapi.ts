// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import sampleOpenApi from "../data/sample-openapi.json";
import sampleReviewValue from "../data/sample-review.v1.json";
import { parseReviewEnvelopeV1 } from "./review-v1";


export const SAMPLE_OPENAPI_SOURCE = `${JSON.stringify(sampleOpenApi, null, 2)}\n`;
export const SAMPLE_REVIEW = parseReviewEnvelopeV1(sampleReviewValue);
