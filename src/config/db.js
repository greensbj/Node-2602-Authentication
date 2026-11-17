const mongoose = require('mongoose');
const { mongoUri } = require('./env');

async function connectDB() {
  mongoose.set('strictQuery', true);

  const conn = await mongoose.connect(mongoUri, {
    serverSelectionTimeoutMS: 10000,
  });

  // eslint-disable-next-line no-console
  console.log(`MongoDB connected: ${conn.connection.host}/${conn.connection.name}`);
  return conn;
}

module.exports = connectDB;
