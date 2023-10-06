var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
const expressSession = require('express-session');
const { Issuer } = require('openid-client');
const axios = require('axios');
const jwt = require('jsonwebtoken');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
const { exit } = require('process');

var app = express();

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(expressSession({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true
}));

let client;

Issuer.discover('https://pf2.synetis.corp:9031/.well-known/openid-configuration')
  .then(issuer => {
    client = new issuer.Client({
      client_id: 'expresso',
      client_secret: 'secret',
      redirect_uris: ['http://pf1.synetis.corp:3000/auth/callback'],
      post_logout_redirect_uris: ['http://localhost:3000/logout/callback'],
      token_endpoint_auth_method: 'client_secret_post'
    });
  });

app.use('/', indexRouter);

app.get('/auth', (req, res) => {
  const authUrl = client.authorizationUrl({
    scope: 'openid magasin',
    response_type: 'code'
  });
  res.redirect(authUrl);
});


app.get('/auth/callback', async (req, res) => {
  const authorizationCode = req.query.code;
  if (!authorizationCode) exit();
  console.log(authorizationCode);

  const params = new URLSearchParams();
  params.append('grant_type', 'authorization_code');
  params.append('code', authorizationCode);
  params.append('redirect_uri', 'http://pf1.synetis.corp:3000/auth/callback');

  const config = {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    auth: {
      username: 'expresso',
      password: 'secret'
    }
  };

  try {
    const tokenResponse = await axios.post('https://pf2.synetis.corp:9031/as/token.oauth2', params, config);
    const accessToken = tokenResponse.data.access_token;

    const userInfoConfig = {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    };

    const userInfoResponse = await axios.get('https://pf2.synetis.corp:9031/idp/userinfo.openid', userInfoConfig);
    const userInfo = userInfoResponse.data;

    req.session.tokenSet = {
      id_token: tokenResponse.data.id_token,
      access_token: accessToken
    };

    // Decode JWT and extract payload
    const decodedIdToken = jwt.decode(tokenResponse.data.id_token);
    const decodedAccessToken = jwt.decode(tokenResponse.data.access_token);

    // Store payload content in req
    req.idtoken = decodedIdToken;
    req.at = decodedAccessToken;

    res.render('users', { user: userInfo, at:  req.at , id: req.idtoken });
  } catch (error) {
    console.error('Error:', error);
    res.status(400).send('Failed');
  }
});

/**
app.get('/auth/callback', async (req, res) => {
  const authorizationCode = req.query.code;
  if(!authorizationCode) exit()
  console.log(authorizationCode)
  const params = new URLSearchParams();
  params.append('grant_type', 'authorization_code');
  params.append('code', authorizationCode);
  params.append('redirect_uri', 'http://pf1.synetis.corp:3000/auth/callback');

  const config = {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    auth: {
      username: 'expresso',
      password: 'secret'
    }
  };

  try {
    const response = await axios.post('https://pf2.synetis.corp:9031/as/token.oauth2', params, config);
    
    // Decode JWT and extract payload
    const decodedIdToken = jwt.decode(response.data.id_token);
    const decodedAccessToken = jwt.decode(response.data.access_token);

    // Store payload content in req
    req.idtoken = decodedIdToken;
    req.at = decodedAccessToken;
    console.log(decodedAccessToken)
    // Store tokens in session
    req.session.tokenSet = {
      id_token: response.data.id_token,
      access_token: response.data.access_token
    };

    res.render('users', { user: req.idtoken, at: req.at });
  } catch (error) {
    console.error('Error fetching token:', error);
    res.status(400).send('Failed to get token');
  }
});
**/
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect(client.endSessionUrl());
});

app.use('/users', usersRouter);

app.use(function(req, res, next) {
  next(createError(404));
});

app.use(function(err, req, res, next) {
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
