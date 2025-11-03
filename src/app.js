const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');
const app = express();
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || '*';

app.use(cors({ origin: FRONTEND_ORIGIN === '*' ? true : FRONTEND_ORIGIN, credentials: true }));
app.use(express.json({limit:'10mb'}));
app.use(express.urlencoded({extended:true}));
app.use(cookieParser());
app.use('/uploads', express.static(path.join(__dirname,'uploads')));

app.get('/', (req,res)=>res.json({ok:true, name:'Akademion API v3.3'}));
app.use('/auth', require('./routes/auth'));
app.use('/users', require('./routes/users'));
app.use('/articles', require('./routes/articles'));


app.use((err, req, res, next)=>{
  console.error('Error:', err);
  res.status(err.status||500).json({error: err.message || 'Server error'});
});

module.exports = app;
