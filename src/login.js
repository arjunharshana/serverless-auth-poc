const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, GetCommand } = require('@aws-sdk/lib-dynamodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { formatResponse } = require('./utils');


const baseClient = new DynamoDBClient({ region: 'us-east-1' });
const docClient = DynamoDBDocumentClient.from(baseClient);
const TABLE_NAME = process.env.USERS_TABLE;
const JWT_SECRET = process.env.JWT_SECRET;

exports.handler = async (event) => {
  try {
    const { email, password } = JSON.parse(event.body);

    if (!email || !password) {
      return formatResponse(400, { error: 'Email and password are required' });
    }

    // look up the user in the database
    const { Item } = await docClient.send(new GetCommand({
      TableName: TABLE_NAME,
      Key: { email } 
    }));

    // If no user is found in the database
    if (!Item) {
      return formatResponse(401, { error: 'Invalid credentials' });
    }

    // Compare the submitted password with the stored hash
    const isMatch = await bcrypt.compare(password, Item.password);
    if (!isMatch) {
      return formatResponse(401, { error: 'Invalid credentials' });
    }

    // Generate a secure JWT
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });

    return formatResponse(200, { 
      message: 'Login successful', 
      token 
    });

  } catch (error) {
    console.error('Login Error:', error);
    return formatResponse(500, { error: 'Internal Server Error' });
  }
};