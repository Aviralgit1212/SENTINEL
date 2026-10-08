import mongoose, {
  Schema,
  type InferSchemaType,
} from 'mongoose'

const EvidenceSchema = new Schema(
  {
    id: {
      type: String,
      required: true,
    },

    category: {
      type: String,
      required: true,
    },

    title: {
      type: String,
      required: true,
    },

    description: {
      type: String,
      required: true,
    },

    severity: {
      type: String,
      enum: [
        'low',
        'medium',
        'high',
        'critical',
      ],
      required: true,
    },

    source: {
      type: String,
      required: true,
    },

    score: {
      type: Number,
      required: true,
      min: 0,
    },
  },
  {
    _id: false,
  },
)

const ScanSchema = new Schema(
  {
    scanId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },

    /*
     * One logical scan operation gets one
     * request ID.
     *
     * It is intentionally optional because
     * older history records don't have it.
     */
    scanRequestId: {
      type: String,
      default: null,
    },

    userId: {
      type: String,
      required: true,
      index: true,
    },

    filename: {
      type: String,
      required: true,
    },

    size: {
      type: Number,
      required: true,
      min: 0,
    },

    extension: {
      type: String,
      default: null,
    },

    detectedExtension: {
      type: String,
      default: null,
    },

    extensionMismatch: {
      type: Boolean,
      default: false,
    },

    mimeType: {
      type: String,
      default: null,
    },

    sha256: {
      type: String,
      required: true,
      index: true,
    },

    status: {
      type: String,
      enum: [
        'analyzing',
        'completed',
        'failed',
      ],
      required: true,
      default: 'analyzing',
    },

    antivirus: {
      engine: {
        type: String,
        default: null,
      },

      available: {
        type: Boolean,
        default: false,
      },

      status: {
        type: String,
        enum: [
          'clean',
          'threat',
          'unavailable',
          'error',
        ],
        default: null,
      },

      details: {
        type: String,
        default: '',
      },
    },

    risk: {
      score: {
        type: Number,
        required: true,
        min: 0,
        max: 100,
      },

      level: {
        type: String,
        enum: [
          'low',
          'medium',
          'high',
          'critical',
        ],
        required: true,
      },
    },

    recommendation: {
      type: String,
      enum: [
        'allow',
        'review',
        'block',
      ],
      required: true,
    },

    evidence: {
      type: [EvidenceSchema],
      default: [],
    },

    pdfAnalysis: {
      type: Schema.Types.Mixed,
      default: null,
    },

    errorMessage: {
      type: String,
      default: null,
    },
  },
  {
    timestamps: true,
  },
)

/*
 * Critical part of the fix:
 *
 * One user cannot create two records for the
 * same logical scan request.
 *
 * The index is partial because older MongoDB
 * records don't have scanRequestId.
 */
ScanSchema.index(
  {
    userId: 1,
    scanRequestId: 1,
  },
  {
    unique: true,

    partialFilterExpression: {
      scanRequestId: {
        $type: 'string',
      },
    },
  },
)

export type ScanDocument =
  InferSchemaType<typeof ScanSchema>

export const Scan =
  mongoose.models.Scan ||
  mongoose.model('Scan', ScanSchema)