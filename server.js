const express = require('express');
const config = require('./config');
const vulnerableRoutes = require('./routes/vulnerable');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/health', (req, res) => {
  res.json({ status: 'ok', note: 'Intentionally vulnerable GHAS test backend' });
});

app.get('/config-check', (req, res) => {
  res.json({
    hasApiKey: Boolean(config.apiKey),
    hasDbPassword: Boolean(config.dbPassword),
  });
});

app.use('/api', vulnerableRoutes);

app.listen(config.port, () => {
  console.log(`GHAS test backend listening on port ${config.port}`);
});
