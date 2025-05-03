require('dotenv').config();
const express = require('express');
const { PrismaClient } = require('@prisma/client');
const cors = require('cors');

const app = express();
const prisma = new PrismaClient();

app.use(cors());
app.use(express.json());

app.post('/predict', async (req, res) => {
  const {
    sourceIP,
    destinationIP,
    sourcePort,
    destinationPort,
    predictedClass,
    confidence,
    metrics,
  } = req.body;

  try {
    const prediction = await prisma.prediction.create({
      data: {
        sourceIP,
        destinationIP,
        sourcePort,
        destinationPort,
        predictedClass,
        confidence,
        metrics, // Save new metrics too
      },
    });
    res.status(201).json(prediction);
  } catch (error) {
    console.error('Error creating prediction:', error);
    res.status(500).json({ error: 'Failed to create prediction' });
  }
});

app.get('/predictions', async (req, res) => {
  try {
    const predictions = await prisma.prediction.findMany({
      orderBy: { createdAt: 'desc' },
    });
    res.json(predictions);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch predictions' });
  }
});

// Create a log entry
app.post('/logs', async (req, res) => {
  const { level, message } = req.body;

  try {
    const log = await prisma.log.create({
      data: { level, message },
    });
    res.status(201).json(log);
  } catch (error) {
    console.error('Error creating log:', error);
    res.status(500).json({ error: 'Failed to create log' });
  }
});

// Get all logs (latest first)
app.get('/logs', async (req, res) => {
  try {
    const logs = await prisma.log.findMany({
      orderBy: { timestamp: 'desc' },
    });
    res.json(logs);
  } catch (error) {
    console.error('Error fetching logs:', error);
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});


const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Traffic Prediction API running on http://localhost:${PORT}`);
});
