// src/register.js
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, PutCommand } = require('@aws-sdk/lib-dynamodb');
const bcrypt = require('bcryptjs');

// Inlined helper to bypass emulator container sync issues
const formatResponse = (statusCode, body) => {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
    body: JSON.stringify(body),
  };
};

const baseClient = new DynamoDBClient({ region: 'us-east-1' });
const docClient = DynamoDBDocumentClient.from(baseClient);
const TABLE_NAME = process.env.USERS_TABLE;

exports.handler = async (event) => {
  try {
    const { email, password } = JSON.parse(event.body);
    if (!email || !password) return formatResponse(400, { error: 'Missing fields' });

    const hashedPassword = await bcrypt.hash(password, 10);

    await docClient.send(new PutCommand({
      TableName: TABLE_NAME,
      Item: {
        email, 
        password: hashedPassword,
        createdAt: new Date().toISOString(),
      },
      ConditionExpression: 'attribute_not_exists(email)'
    }));

    return formatResponse(201, { message: 'User registered' });

  } catch (error) {
    if (error.name === 'ConditionalCheckFailedException') {
      return formatResponse(409, { error: 'User already exists' });
    }
    return formatResponse(500, { error: 'Internal Server Error' });
  }
};