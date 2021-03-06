import express, { json, urlencoded } from 'express';
import cors from 'cors';
import path from 'path';
import dbase from './database/config/database';
import routes from './routes';
import logger from './middlewares/logger';

dbase.authenticate().then(() => {
  console.log('database connected...');
});

const app = express();

app.use(cors());
app.use(json());
app.use(urlencoded({ extended: true }));

app.use('/chat', express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

app.use(logger);
app.get('/', (req, res) => {
  res.redirect('/api/docs');
});

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header(
    'Access-Control-Allow-Headers',
    'Origin, X-Requested-With, Content-Type, Accept'
  );
  next();
});

app.use('/api', routes);

export default app;
