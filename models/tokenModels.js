import mongoose, { Schema } from 'mongoose';

const tokenSchema = new mongoose.Schema({
  // userId: {
  //   type: String,
  //   ref: 'user',
  //   required: true,
  // },
  userId: {
    type: Schema.Types.ObjectId,
    unique: true,
    ref: 'user',
    required: true,
  },
  token: {
    type: String,
    required: true,
  },
  createdAt: { type: Date, default: Date.now(), expires: 3600 },
});

const Token = mongoose.model('Token', tokenSchema);

export default Token;
