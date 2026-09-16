const mongoose = require("mongoose");

const historyItemSchema = new mongoose.Schema(
  {
    id: { type: String, default: () => new mongoose.Types.ObjectId().toString() },
    type: { type: String, required: true },
    amount: { type: Number, default: 0 },
    status: { type: String, default: "Completed" },
    utr: { type: String, default: undefined },
    upi: { type: String, default: undefined },
    baji: { type: Number, default: undefined },
    betType: { type: String, default: undefined },
    rawTarget: { type: String, default: undefined },
    target: { type: String, default: undefined },
    stake: { type: Number, default: undefined },
    payout: { type: Number, default: undefined },
    details: { type: String, default: "" },
    date: { type: Date, default: Date.now },
    reviewedAt: { type: Date, default: undefined }
  },
  { _id: false, minimize: false }
);

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3,
      maxlength: 24
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true
    },

    password: {
      type: String,
      required: true
    },

    balance: {
      type: Number,
      default: 0,
      min: 0
    },

    // Only rewards won from games are withdrawable.
    winningBalance: {
      type: Number,
      default: 0,
      min: 0
    },

    isAdmin: {
      type: Boolean,
      default: false
    },

    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user"
    },

    totalPredictions: {
      type: Number,
      default: 0
    },

    wins: {
      type: Number,
      default: 0
    },

    losses: {
      type: Number,
      default: 0
    },

    totalBet: {
      type: Number,
      default: 0
    },

    depositHistory: {
      type: [historyItemSchema],
      default: []
    },

    withdrawalHistory: {
      type: [historyItemSchema],
      default: []
    },

    transactionHistory: {
      type: [historyItemSchema],
      default: []
    },

    // Permanent per-user game/bet activity. Kept separately so wallet
    // history and game history can never overwrite/hide each other.
    gameHistory: {
      type: [historyItemSchema],
      default: []
    },

    resetOtpHash: {
      type: String,
      default: null,
      select: false
    },

    resetOtpExpires: {
      type: Date,
      default: null,
      select: false
    },

    resetOtpAttempts: {
      type: Number,
      default: 0,
      select: false
    },

    // Increment this to invalidate every previously issued JWT for the user.
    tokenVersion: {
      type: Number,
      default: 0,
      select: false
    }
  },
  { timestamps: true, optimisticConcurrency: true }
);

userSchema.pre("save", function(next) {
  if (this.role === "admin") this.isAdmin = true;
  if (this.isAdmin) this.role = "admin";
  next();
});

module.exports = mongoose.model("User", userSchema);
