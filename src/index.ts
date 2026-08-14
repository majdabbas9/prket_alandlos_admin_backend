import app from './app';
import dotenv from 'dotenv';
import { getLogger } from './utils/logger';

dotenv.config();
const logger = getLogger(__filename);

const PORT = process.env.PORT || 5001;

app.listen(PORT, () => {
  logger.info(`Auth Server running on port ${PORT}`);
});
