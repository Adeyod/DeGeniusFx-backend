import mongoose from 'mongoose';
import dotenv from 'dotenv';
dotenv.config();

const DBConfig = mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log(
      `MongoDB connected successfully to ${mongoose.connection.host}`
    );
  })
  .catch((error) => {
    console.log(error);
  });

export default DBConfig;
