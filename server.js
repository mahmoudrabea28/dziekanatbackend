require('dotenv').config();
const connect = require('./src/utils/db');
const app = require('./src/app');
const PORT = process.env.PORT || 8383;
(async () => {
  await connect();
  app.listen(PORT, () => console.log(`API listening on http://localhost:${PORT}`));
})();
