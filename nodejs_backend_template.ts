# Node.js TypeScript Backend Template

A comprehensive backend template with Docker, MongoDB/Mongoose, Authentication, GraphQL, and REST APIs.

## Project Structure

```
src/
├── config/
│   ├── database.ts
│   ├── env.ts
│   └── apollo.ts
├── models/
│   ├── User.ts
│   ├── Post.ts
│   └── index.ts
├── middleware/
│   ├── auth.ts
│   ├── errorHandler.ts
│   └── validation.ts
├── controllers/
│   ├── authController.ts
│   ├── userController.ts
│   └── postController.ts
├── services/
│   ├── authService.ts
│   ├── userService.ts
│   └── postService.ts
├── routes/
│   ├── auth.ts
│   ├── users.ts
│   └── posts.ts
├── graphql/
│   ├── typeDefs/
│   │   ├── user.ts
│   │   ├── post.ts
│   │   └── index.ts
│   ├── resolvers/
│   │   ├── userResolver.ts
│   │   ├── postResolver.ts
│   │   └── index.ts
│   └── context.ts
├── types/
│   ├── auth.ts
│   └── index.ts
├── utils/
│   ├── jwt.ts
│   ├── validation.ts
│   └── logger.ts
└── app.ts
└── server.ts
```

## Package.json

```json
{
  "name": "nodejs-backend-template",
  "version": "1.0.0",
  "description": "Node.js TypeScript Backend Template with GraphQL, MongoDB, and Authentication",
  "main": "dist/server.js",
  "scripts": {
    "dev": "nodemon src/server.ts",
    "build": "tsc",
    "start": "node dist/server.js",
    "lint": "eslint src/**/*.ts",
    "test": "jest"
  },
  "dependencies": {
    "@apollo/server": "^4.10.0",
    "@graphql-tools/schema": "^10.0.0",
    "apollo-server-express": "^3.12.1",
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "express": "^4.18.2",
    "express-rate-limit": "^7.1.5",
    "graphql": "^16.8.1",
    "helmet": "^7.1.0",
    "joi": "^17.11.0",
    "jsonwebtoken": "^9.0.2",
    "mongoose": "^8.0.3",
    "winston": "^3.11.0"
  },
  "devDependencies": {
    "@types/bcryptjs": "^2.4.6",
    "@types/cors": "^2.8.17",
    "@types/express": "^4.17.21",
    "@types/jest": "^29.5.8",
    "@types/jsonwebtoken": "^9.0.5",
    "@types/node": "^20.9.2",
    "@typescript-eslint/eslint-plugin": "^6.12.0",
    "@typescript-eslint/parser": "^6.12.0",
    "eslint": "^8.54.0",
    "jest": "^29.7.0",
    "nodemon": "^3.0.1",
    "ts-jest": "^29.1.1",
    "ts-node": "^10.9.1",
    "typescript": "^5.2.2"
  }
}
```

## Docker Configuration

### Dockerfile

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

RUN npm run build

EXPOSE 4000

CMD ["npm", "start"]
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "4000:4000"
    environment:
      - NODE_ENV=production
      - MONGODB_URI=mongodb://mongodb:27017/myapp
      - JWT_SECRET=your-super-secret-jwt-key
      - JWT_EXPIRE=7d
    depends_on:
      - mongodb
    volumes:
      - .:/app
      - /app/node_modules

  mongodb:
    image: mongo:7
    ports:
      - "27017:27017"
    volumes:
      - mongodb_data:/data/db
    environment:
      - MONGO_INITDB_DATABASE=myapp

volumes:
  mongodb_data:
```

### docker-compose.dev.yml

```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "4000:4000"
    environment:
      - NODE_ENV=development
      - MONGODB_URI=mongodb://mongodb:27017/myapp_dev
      - JWT_SECRET=dev-secret-key
      - JWT_EXPIRE=1d
    depends_on:
      - mongodb
    volumes:
      - .:/app
      - /app/node_modules
    command: npm run dev

  mongodb:
    image: mongo:7
    ports:
      - "27017:27017"
    volumes:
      - mongodb_dev_data:/data/db

volumes:
  mongodb_dev_data:
```

## TypeScript Configuration

### tsconfig.json

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "**/*.test.ts"]
}
```

## Environment Configuration

### src/config/env.ts

```typescript
import { config } from 'dotenv';

config();

export const ENV = {
  NODE_ENV: process.env.NODE_ENV || 'development',
  PORT: parseInt(process.env.PORT || '4000'),
  MONGODB_URI: process.env.MONGODB_URI || 'mongodb://localhost:27017/myapp',
  JWT_SECRET: process.env.JWT_SECRET || 'fallback-secret-key',
  JWT_EXPIRE: process.env.JWT_EXPIRE || '7d',
  BCRYPT_ROUNDS: parseInt(process.env.BCRYPT_ROUNDS || '12'),
} as const;

export const isDevelopment = ENV.NODE_ENV === 'development';
export const isProduction = ENV.NODE_ENV === 'production';
```

## Database Configuration

### src/config/database.ts

```typescript
import mongoose from 'mongoose';
import { ENV } from './env';
import { logger } from '../utils/logger';

export const connectDB = async (): Promise<void> => {
  try {
    const conn = await mongoose.connect(ENV.MONGODB_URI);
    logger.info(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    logger.error('Database connection error:', error);
    process.exit(1);
  }
};

// Graceful disconnect
export const disconnectDB = async (): Promise<void> => {
  try {
    await mongoose.disconnect();
    logger.info('MongoDB Disconnected');
  } catch (error) {
    logger.error('Database disconnection error:', error);
  }
};
```

## Models

### src/models/User.ts

```typescript
import { Schema, model, Document } from 'mongoose';
import bcrypt from 'bcryptjs';

export interface IUser extends Document {
  username: string;
  email: string;
  password: string;
  role: 'user' | 'admin';
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
  comparePassword(candidatePassword: string): Promise<boolean>;
}

const userSchema = new Schema<IUser>({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6,
    select: false
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword: string): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.password);
};

export const User = model<IUser>('User', userSchema);
```

### src/models/Post.ts

```typescript
import { Schema, model, Document, Types } from 'mongoose';

export interface IPost extends Document {
  title: string;
  content: string;
  author: Types.ObjectId;
  tags: string[];
  isPublished: boolean;
  publishedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

const postSchema = new Schema<IPost>({
  title: {
    type: String,
    required: true,
    trim: true,
    maxlength: 200
  },
  content: {
    type: String,
    required: true,
    maxlength: 10000
  },
  author: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  tags: [{
    type: String,
    trim: true,
    lowercase: true
  }],
  isPublished: {
    type: Boolean,
    default: false
  },
  publishedAt: {
    type: Date
  }
}, {
  timestamps: true
});

// Set publishedAt when isPublished becomes true
postSchema.pre('save', function(next) {
  if (this.isModified('isPublished') && this.isPublished && !this.publishedAt) {
    this.publishedAt = new Date();
  }
  next();
});

export const Post = model<IPost>('Post', postSchema);
```

## Authentication Types

### src/types/auth.ts

```typescript
import { Request } from 'express';
import { IUser } from '../models/User';

export interface AuthRequest extends Request {
  user?: IUser;
}

export interface JWTPayload {
  userId: string;
  role: string;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterCredentials {
  username: string;
  email: string;
  password: string;
}
```

## JWT Utils

### src/utils/jwt.ts

```typescript
import jwt from 'jsonwebtoken';
import { ENV } from '../config/env';
import { JWTPayload } from '../types/auth';

export const generateToken = (payload: JWTPayload): string => {
  return jwt.sign(payload, ENV.JWT_SECRET, {
    expiresIn: ENV.JWT_EXPIRE,
  });
};

export const verifyToken = (token: string): JWTPayload => {
  return jwt.verify(token, ENV.JWT_SECRET) as JWTPayload;
};
```

## Logger Utility

### src/utils/logger.ts

```typescript
import winston from 'winston';
import { ENV, isDevelopment } from '../config/env';

const logger = winston.createLogger({
  level: isDevelopment ? 'debug' : 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'backend-api' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
  ],
});

if (isDevelopment) {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

export { logger };
```

## Middleware

### src/middleware/auth.ts

```typescript
import { Response, NextFunction } from 'express';
import { User } from '../models/User';
import { verifyToken } from '../utils/jwt';
import { AuthRequest } from '../types/auth';

export const authenticate = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const token = authHeader.substring(7);
    const decoded = verifyToken(token);
    
    const user = await User.findById(decoded.userId);
    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'Invalid or inactive user' });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

export const authorize = (...roles: string[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
};
```

### src/middleware/errorHandler.ts

```typescript
import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';

export interface AppError extends Error {
  statusCode?: number;
  isOperational?: boolean;
}

export const errorHandler = (
  err: AppError,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  let error = { ...err };
  error.message = err.message;

  // Log error
  logger.error(err);

  // Mongoose bad ObjectId
  if (err.name === 'CastError') {
    const message = 'Resource not found';
    error = { ...error, message, statusCode: 404 };
  }

  // Mongoose duplicate key
  if ((err as any).code === 11000) {
    const message = 'Duplicate field value entered';
    error = { ...error, message, statusCode: 400 };
  }

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const message = Object.values((err as any).errors).map((val: any) => val.message);
    error = { ...error, message, statusCode: 400 };
  }

  res.status(error.statusCode || 500).json({
    success: false,
    error: error.message || 'Server Error'
  });
};
```

## Services

### src/services/authService.ts

```typescript
import { User, IUser } from '../models/User';
import { generateToken } from '../utils/jwt';
import { LoginCredentials, RegisterCredentials } from '../types/auth';

export class AuthService {
  static async register(userData: RegisterCredentials): Promise<{ user: IUser; token: string }> {
    const existingUser = await User.findOne({
      $or: [{ email: userData.email }, { username: userData.username }]
    });

    if (existingUser) {
      throw new Error('User already exists with this email or username');
    }

    const user = await User.create(userData);
    const token = generateToken({ userId: user._id.toString(), role: user.role });

    return { user, token };
  }

  static async login(credentials: LoginCredentials): Promise<{ user: IUser; token: string }> {
    const user = await User.findOne({ email: credentials.email }).select('+password');

    if (!user || !(await user.comparePassword(credentials.password))) {
      throw new Error('Invalid email or password');
    }

    if (!user.isActive) {
      throw new Error('Account is deactivated');
    }

    const token = generateToken({ userId: user._id.toString(), role: user.role });

    return { user, token };
  }

  static async getProfile(userId: string): Promise<IUser> {
    const user = await User.findById(userId);
    if (!user) {
      throw new Error('User not found');
    }
    return user;
  }
}
```

### src/services/userService.ts

```typescript
import { User, IUser } from '../models/User';

export class UserService {
  static async getAllUsers(page = 1, limit = 10): Promise<{ users: IUser[]; total: number }> {
    const skip = (page - 1) * limit;
    
    const [users, total] = await Promise.all([
      User.find({ isActive: true }).skip(skip).limit(limit),
      User.countDocuments({ isActive: true })
    ]);

    return { users, total };
  }

  static async getUserById(id: string): Promise<IUser> {
    const user = await User.findById(id);
    if (!user) {
      throw new Error('User not found');
    }
    return user;
  }

  static async updateUser(id: string, updateData: Partial<IUser>): Promise<IUser> {
    const user = await User.findByIdAndUpdate(id, updateData, { new: true });
    if (!user) {
      throw new Error('User not found');
    }
    return user;
  }

  static async deleteUser(id: string): Promise<void> {
    const user = await User.findByIdAndUpdate(id, { isActive: false });
    if (!user) {
      throw new Error('User not found');
    }
  }
}
```

### src/services/postService.ts

```typescript
import { Post, IPost } from '../models/Post';

export class PostService {
  static async createPost(postData: Partial<IPost>): Promise<IPost> {
    const post = await Post.create(postData);
    return post.populate('author', 'username email');
  }

  static async getAllPosts(page = 1, limit = 10, published?: boolean): Promise<{ posts: IPost[]; total: number }> {
    const skip = (page - 1) * limit;
    const filter = published !== undefined ? { isPublished: published } : {};
    
    const [posts, total] = await Promise.all([
      Post.find(filter)
        .populate('author', 'username email')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit),
      Post.countDocuments(filter)
    ]);

    return { posts, total };
  }

  static async getPostById(id: string): Promise<IPost> {
    const post = await Post.findById(id).populate('author', 'username email');
    if (!post) {
      throw new Error('Post not found');
    }
    return post;
  }

  static async updatePost(id: string, updateData: Partial<IPost>, userId: string): Promise<IPost> {
    const post = await Post.findOneAndUpdate(
      { _id: id, author: userId },
      updateData,
      { new: true }
    ).populate('author', 'username email');
    
    if (!post) {
      throw new Error('Post not found or unauthorized');
    }
    return post;
  }

  static async deletePost(id: string, userId: string): Promise<void> {
    const result = await Post.findOneAndDelete({ _id: id, author: userId });
    if (!result) {
      throw new Error('Post not found or unauthorized');
    }
  }
}
```

## Controllers

### src/controllers/authController.ts

```typescript
import { Request, Response, NextFunction } from 'express';
import { AuthService } from '../services/authService';
import { AuthRequest } from '../types/auth';

export class AuthController {
  static async register(req: Request, res: Response, next: NextFunction) {
    try {
      const { user, token } = await AuthService.register(req.body);
      
      res.status(201).json({
        success: true,
        data: { user, token }
      });
    } catch (error) {
      next(error);
    }
  }

  static async login(req: Request, res: Response, next: NextFunction) {
    try {
      const { user, token } = await AuthService.login(req.body);
      
      res.json({
        success: true,
        data: { user, token }
      });
    } catch (error) {
      next(error);
    }
  }

  static async getProfile(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const user = await AuthService.getProfile(req.user!._id);
      
      res.json({
        success: true,
        data: user
      });
    } catch (error) {
      next(error);
    }
  }
}
```

## Routes

### src/routes/auth.ts

```typescript
import { Router } from 'express';
import { AuthController } from '../controllers/authController';
import { authenticate } from '../middleware/auth';

const router = Router();

router.post('/register', AuthController.register);
router.post('/login', AuthController.login);
router.get('/profile', authenticate, AuthController.getProfile);

export default router;
```

## GraphQL Configuration

### src/graphql/typeDefs/user.ts

```typescript
import { gql } from 'apollo-server-express';

export const userTypeDefs = gql`
  type User {
    id: ID!
    username: String!
    email: String!
    role: Role!
    isActive: Boolean!
    createdAt: String!
    updatedAt: String!
  }

  enum Role {
    USER
    ADMIN
  }

  type AuthPayload {
    user: User!
    token: String!
  }

  input RegisterInput {
    username: String!
    email: String!
    password: String!
  }

  input LoginInput {
    email: String!
    password: String!
  }

  extend type Query {
    me: User
    users(page: Int, limit: Int): UsersResponse!
  }

  extend type Mutation {
    register(input: RegisterInput!): AuthPayload!
    login(input: LoginInput!): AuthPayload!
  }

  type UsersResponse {
    users: [User!]!
    total: Int!
  }
`;
```

### src/graphql/typeDefs/post.ts

```typescript
import { gql } from 'apollo-server-express';

export const postTypeDefs = gql`
  type Post {
    id: ID!
    title: String!
    content: String!
    author: User!
    tags: [String!]!
    isPublished: Boolean!
    publishedAt: String
    createdAt: String!
    updatedAt: String!
  }

  input CreatePostInput {
    title: String!
    content: String!
    tags: [String!]
    isPublished: Boolean
  }

  input UpdatePostInput {
    title: String
    content: String
    tags: [String!]
    isPublished: Boolean
  }

  extend type Query {
    posts(page: Int, limit: Int, published: Boolean): PostsResponse!
    post(id: ID!): Post
  }

  extend type Mutation {
    createPost(input: CreatePostInput!): Post!
    updatePost(id: ID!, input: UpdatePostInput!): Post!
    deletePost(id: ID!): Boolean!
  }

  type PostsResponse {
    posts: [Post!]!
    total: Int!
  }
`;
```

### src/graphql/typeDefs/index.ts

```typescript
import { gql } from 'apollo-server-express';
import { userTypeDefs } from './user';
import { postTypeDefs } from './post';

const rootTypeDefs = gql`
  type Query {
    _empty: String
  }

  type Mutation {
    _empty: String
  }
`;

export const typeDefs = [rootTypeDefs, userTypeDefs, postTypeDefs];
```

### src/graphql/resolvers/userResolver.ts

```typescript
import { AuthService } from '../../services/authService';
import { UserService } from '../../services/userService';
import { AuthenticationError } from 'apollo-server-express';

export const userResolvers = {
  Query: {
    me: async (_: any, __: any, { user }: any) => {
      if (!user) {
        throw new AuthenticationError('Not authenticated');
      }
      return user;
    },

    users: async (_: any, { page = 1, limit = 10 }: any, { user }: any) => {
      if (!user || user.role !== 'admin') {
        throw new AuthenticationError('Admin access required');
      }
      return await UserService.getAllUsers(page, limit);
    },
  },

  Mutation: {
    register: async (_: any, { input }: any) => {
      return await AuthService.register(input);
    },

    login: async (_: any, { input }: any) => {
      return await AuthService.login(input);
    },
  },
};
```

### src/graphql/resolvers/postResolver.ts

```typescript
import { PostService } from '../../services/postService';
import { AuthenticationError } from 'apollo-server-express';

export const postResolvers = {
  Query: {
    posts: async (_: any, { page = 1, limit = 10, published }: any) => {
      return await PostService.getAllPosts(page, limit, published);
    },

    post: async (_: any, { id }: any) => {
      return await PostService.getPostById(id);
    },
  },

  Mutation: {
    createPost: async (_: any, { input }: any, { user }: any) => {
      if (!user) {
        throw new AuthenticationError('Not authenticated');
      }
      return await PostService.createPost({ ...input, author: user._id });
    },

    updatePost: async (_: any, { id, input }: any, { user }: any) => {
      if (!user) {
        throw new AuthenticationError('Not authenticated');
      }
      return await PostService.updatePost(id, input, user._id);
    },

    deletePost: async (_: any, { id }: any, { user }: any) => {
      if (!user) {
        throw new AuthenticationError('Not authenticated');
      }
      await PostService.deletePost(id, user._id);
      return true;
    },
  },
};
```

### src/graphql/resolvers/index.ts

```typescript
import { userResolvers } from './userResolver';
import { postResolvers } from './postResolver';

export const resolvers = [userResolvers, postResolvers];
```

### src/graphql/context.ts

```typescript
import { Request } from 'express';
import { User } from '../models/User';
import { verifyToken } from '../utils/jwt';

export interface GraphQLContext {
  user?: any;
}

export const createContext = async ({ req }: { req: Request }): Promise<GraphQLContext> => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return {};
  }

  try {
    const token = authHeader.substring(7);
    const decoded = verifyToken(token);
    const user = await User.findById(decoded.userId);
    
    if (user && user.isActive) {
      return { user };
    }
  } catch (error) {
    // Invalid token, continue without user
  }

  return {};
};
```

### src/config/apollo.ts

```typescript
import { ApolloServer } from 'apollo-server-express';
import { typeDefs } from '../graphql/typeDefs';
import { resolvers } from '../graphql/resolvers';
import { createContext } from '../graphql/context';

export const createApolloServer = () => {
  return new ApolloServer({
    typeDefs,
    resolvers,
    context: createContext,
    introspection: true,
    playground: true,
  });
};
```

## Main Application Files

### src/app.ts

```typescript
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { errorHandler } from './middleware/errorHandler';
import authRoutes from './routes/auth';

const app = express();

// Security middleware
app.use(helmet());
app.use(cors());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// API routes
app.use('/api/auth', authRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Error handling
app.use(errorHandler);

export default app;
```

### src/server.ts

```typescript
import app from './app';
import { ENV } from './config/env';
import { connectDB } from './config/database';
import { createApolloServer } from './config/apollo';
import { logger } from './utils/logger';

const startServer = async () => {
  try {
    // Connect to database
    await connectDB();

    // Create Apollo Server
    const apolloServer = createApolloServer();
    await apolloServer.start();

    // Apply Apollo GraphQL middleware
    apolloServer.applyMiddleware({ app, path: '/graphql' });

    // Start HTTP server
    const server = app.listen(ENV.PORT, () => {
      logger.info(`🚀 Server ready at http://localhost:${ENV.PORT}`);
      logger.info(`📊 GraphQL ready at http://localhost:${ENV.PORT}${apolloServer.graphqlPath}`);
      logger.info(`🏥 Health check at http://localhost:${ENV.PORT}/health`);
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      logger.info('SIGTERM received, shutting down gracefully');
      server.close(() => {
        logger.info('Process terminated');
        process.exit(0);
      });
    });

  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();
```

## Additional Controllers

### src/controllers/userController.ts

```typescript
import { Request, Response, NextFunction } from 'express';
import { UserService } from '../services/userService';
import { AuthRequest } from '../types/auth';

export class UserController {
  static async getAllUsers(req: Request, res: Response, next: NextFunction) {
    try {
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 10;
      
      const result = await UserService.getAllUsers(page, limit);
      
      res.json({
        success: true,
        data: result,
        pagination: {
          page,
          limit,
          total: result.total,
          pages: Math.ceil(result.total / limit)
        }
      });
    } catch (error) {
      next(error);
    }
  }

  static async getUserById(req: Request, res: Response, next: NextFunction) {
    try {
      const user = await UserService.getUserById(req.params.id);
      
      res.json({
        success: true,
        data: user
      });
    } catch (error) {
      next(error);
    }
  }

  static async updateUser(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userId = req.params.id;
      
      // Users can only update their own profile unless they're admin
      if (req.user!._id.toString() !== userId && req.user!.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
      }

      const user = await UserService.updateUser(userId, req.body);
      
      res.json({
        success: true,
        data: user
      });
    } catch (error) {
      next(error);
    }
  }

  static async deleteUser(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      await UserService.deleteUser(req.params.id);
      
      res.json({
        success: true,
        message: 'User deleted successfully'
      });
    } catch (error) {
      next(error);
    }
  }
}
```

### src/controllers/postController.ts

```typescript
import { Request, Response, NextFunction } from 'express';
import { PostService } from '../services/postService';
import { AuthRequest } from '../types/auth';

export class PostController {
  static async createPost(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const postData = {
        ...req.body,
        author: req.user!._id
      };
      
      const post = await PostService.createPost(postData);
      
      res.status(201).json({
        success: true,
        data: post
      });
    } catch (error) {
      next(error);
    }
  }

  static async getAllPosts(req: Request, res: Response, next: NextFunction) {
    try {
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 10;
      const published = req.query.published === 'true' ? true : req.query.published === 'false' ? false : undefined;
      
      const result = await PostService.getAllPosts(page, limit, published);
      
      res.json({
        success: true,
        data: result,
        pagination: {
          page,
          limit,
          total: result.total,
          pages: Math.ceil(result.total / limit)
        }
      });
    } catch (error) {
      next(error);
    }
  }

  static async getPostById(req: Request, res: Response, next: NextFunction) {
    try {
      const post = await PostService.getPostById(req.params.id);
      
      res.json({
        success: true,
        data: post
      });
    } catch (error) {
      next(error);
    }
  }

  static async updatePost(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const post = await PostService.updatePost(
        req.params.id,
        req.body,
        req.user!._id.toString()
      );
      
      res.json({
        success: true,
        data: post
      });
    } catch (error) {
      next(error);
    }
  }

  static async deletePost(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      await PostService.deletePost(req.params.id, req.user!._id.toString());
      
      res.json({
        success: true,
        message: 'Post deleted successfully'
      });
    } catch (error) {
      next(error);
    }
  }
}
```

## Additional Routes

### src/routes/users.ts

```typescript
import { Router } from 'express';
import { UserController } from '../controllers/userController';
import { authenticate, authorize } from '../middleware/auth';

const router = Router();

router.get('/', authenticate, authorize('admin'), UserController.getAllUsers);
router.get('/:id', authenticate, UserController.getUserById);
router.put('/:id', authenticate, UserController.updateUser);
router.delete('/:id', authenticate, authorize('admin'), UserController.deleteUser);

export default router;
```

### src/routes/posts.ts

```typescript
import { Router } from 'express';
import { PostController } from '../controllers/postController';
import { authenticate } from '../middleware/auth';

const router = Router();

router.post('/', authenticate, PostController.createPost);
router.get('/', PostController.getAllPosts);
router.get('/:id', PostController.getPostById);
router.put('/:id', authenticate, PostController.updatePost);
router.delete('/:id', authenticate, PostController.deletePost);

export default router;
```

## Validation Middleware

### src/middleware/validation.ts

```typescript
import Joi from 'joi';
import { Request, Response, NextFunction } from 'express';

export const validateBody = (schema: Joi.ObjectSchema) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const { error } = schema.validate(req.body);
    
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message
      });
    }
    
    next();
  };
};

// Validation schemas
export const registerSchema = Joi.object({
  username: Joi.string().min(3).max(30).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required()
});

export const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

export const createPostSchema = Joi.object({
  title: Joi.string().max(200).required(),
  content: Joi.string().max(10000).required(),
  tags: Joi.array().items(Joi.string()),
  isPublished: Joi.boolean()
});

export const updatePostSchema = Joi.object({
  title: Joi.string().max(200),
  content: Joi.string().max(10000),
  tags: Joi.array().items(Joi.string()),
  isPublished: Joi.boolean()
});
```

## Updated App with All Routes

### Updated src/app.ts

```typescript
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { errorHandler } from './middleware/errorHandler';
import authRoutes from './routes/auth';
import userRoutes from './routes/users';
import postRoutes from './routes/posts';

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false, // Disable for GraphQL playground
}));
app.use(cors());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
});
app.use('/api/', limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/posts', postRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Route not found'
  });
});

// Error handling middleware (must be last)
app.use(errorHandler);

export default app;
```

## Environment Variables Template

### .env.example

```bash
NODE_ENV=development
PORT=4000

# Database
MONGODB_URI=mongodb://localhost:27017/myapp

# JWT
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRE=7d

# Bcrypt
BCRYPT_ROUNDS=12

# Logging
LOG_LEVEL=info
```

## Scripts for Development

### scripts/dev-setup.sh

```bash
#!/bin/bash

echo "🚀 Setting up development environment..."

# Copy environment file
if [ ! -f .env ]; then
    cp .env.example .env
    echo "✅ Created .env file from template"
fi

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Create logs directory
mkdir -p logs

# Start MongoDB with Docker Compose
echo "🍃 Starting MongoDB..."
docker-compose -f docker-compose.dev.yml up -d mongodb

echo "✅ Development environment setup complete!"
echo "🏃 Run 'npm run dev' to start the development server"
```

### scripts/docker-build.sh

```bash
#!/bin/bash

echo "🐳 Building Docker image..."
docker build -t nodejs-backend-template .

echo "✅ Docker image built successfully!"
echo "🏃 Run 'docker-compose up' to start the application"
```

## Testing Setup

### jest.config.js

```javascript
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/types/**/*',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
};
```

### src/__tests__/auth.test.ts

```typescript
import request from 'supertest';
import app from '../app';
import { connectDB, disconnectDB } from '../config/database';

describe('Auth Endpoints', () => {
  beforeAll(async () => {
    await connectDB();
  });

  afterAll(async () => {
    await disconnectDB();
  });

  describe('POST /api/auth/register', () => {
    it('should register a new user', async () => {
      const userData = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.user.email).toBe(userData.email);
      expect(response.body.data.token).toBeDefined();
    });
  });

  describe('POST /api/auth/login', () => {
    it('should login with valid credentials', async () => {
      const credentials = {
        email: 'test@example.com',
        password: 'password123'
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(credentials)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.token).toBeDefined();
    });
  });
});
```

## Package Scripts Update

```json
{
  "scripts": {
    "dev": "nodemon src/server.ts",
    "build": "tsc",
    "start": "node dist/server.js",
    "lint": "eslint src/**/*.ts --fix",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "docker:build": "docker build -t nodejs-backend-template .",
    "docker:dev": "docker-compose -f docker-compose.dev.yml up",
    "docker:prod": "docker-compose up"
  }
}
```

## README.md

```markdown
# Node.js TypeScript Backend Template

A production-ready backend template featuring Node.js, TypeScript, MongoDB, GraphQL, REST APIs, and Docker.

## Features

- 🚀 **Node.js** with **TypeScript**
- 🍃 **MongoDB** with **Mongoose** ODM
- 🔐 **JWT Authentication & Authorization**
- 📊 **GraphQL** API with Apollo Server
- 🛣️ **REST APIs** with Express
- 🐳 **Docker** support with multi-stage builds
- 🧪 **Testing** setup with Jest
- 📝 **Comprehensive logging** with Winston
- 🛡️ **Security** middleware (Helmet, CORS, Rate limiting)
- ✅ **Input validation** with Joi
- 📁 **Clean architecture** (Routes → Controllers → Services)

## Quick Start

1. **Clone and setup**:
   ```bash
   git clone <repository>
   cd nodejs-backend-template
   chmod +x scripts/dev-setup.sh
   ./scripts/dev-setup.sh
   ```

2. **Start development server**:
   ```bash
   npm run dev
   ```

3. **Access the APIs**:
   - REST API: http://localhost:4000/api
   - GraphQL Playground: http://localhost:4000/graphql
   - Health Check: http://localhost:4000/health

## Docker Usage

```bash
# Development
npm run docker:dev

# Production
npm run docker:prod
```

## API Examples

### REST API Examples

**Register User**:
```bash
curl -X POST http://localhost:4000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"john","email":"john@example.com","password":"password123"}'
```

**Create Post**:
```bash
curl -X POST http://localhost:4000/api/posts \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"title":"My Post","content":"Hello World!","tags":["tech"]}'
```

### GraphQL Examples

**Register User**:
```graphql
mutation {
  register(input: {
    username: "john"
    email: "john@example.com"
    password: "password123"
  }) {
    user {
      id
      username
      email
    }
    token
  }
}
```

**Query Posts**:
```graphql
query {
  posts(page: 1, limit: 10) {
    posts {
      id
      title
      content
      author {
        username
      }
      createdAt
    }
    total
  }
}
```

## Testing

```bash
npm test                 # Run tests
npm run test:watch      # Watch mode
npm run test:coverage   # With coverage
```

## Project Structure

The template follows a clean, scalable architecture:

- **Models**: Mongoose schemas and interfaces
- **Controllers**: HTTP request handlers
- **Services**: Business logic layer
- **Routes**: API endpoint definitions
- **Middleware**: Authentication, validation, error handling
- **GraphQL**: Type definitions and resolvers
- **Utils**: Shared utilities (JWT, logging, etc.)

## Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
NODE_ENV=development
PORT=4000
MONGODB_URI=mongodb://localhost:27017/myapp
JWT_SECRET=your-secret-key
JWT_EXPIRE=7d
```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License
```

## .gitignore

```.gitignore
# Logs
logs
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*
lerna-debug.log*
.pnpm-debug.log*

# Diagnostic reports (https://nodejs.org/api/report.html)
report.[0-9]*.[0-9]*.[0-9]*.[0-9]*.json

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Directory for instrumented libs generated by jscoverage/JSCover
lib-cov

# Coverage directory used by tools like istanbul
coverage
*.lcov

# nyc test coverage
.nyc_output

# Grunt intermediate storage (https://gruntjs.com/creating-plugins#storing-task-files)
.grunt

# Bower dependency directory (https://bower.io/)
bower_components

# node-waf configuration
.lock-wscript

# Compiled binary addons (https://nodejs.org/api/addons.html)
build/Release

# Dependency directories
node_modules/
jspm_packages/

# Snowpack dependency directory (https://snowpack.dev/)
web_modules/

# TypeScript cache
*.tsbuildinfo

# Optional npm cache directory
.npm

# Optional eslint cache
.eslintcache

# Optional stylelint cache
.stylelintcache

# Microbundle cache
.rpt2_cache/
.rts2_cache_cjs/
.rts2_cache_es/
.rts2_cache_umd/

# Optional REPL history
.node_repl_history

# Output of 'npm pack'
*.tgz

# Yarn Integrity file
.yarn-integrity

# dotenv environment variable files
.env
.env.development.local
.env.test.local
.env.production.local
.env.local

# parcel-bundler cache (https://parceljs.org/)
.cache
.parcel-cache

# Next.js build output
.next
out

# Nuxt.js build / generate output
.nuxt
dist

# Gatsby files
.cache/
# Comment in the public line in if your project uses Gatsby and not Next.js
# https://nextjs.org/blog/next-9-1#public-directory-support
# public

# vuepress build output
.vuepress/dist

# vuepress v2.x temp and cache directory
.temp
.cache

# Docusaurus cache and generated files
.docusaurus

# Serverless directories
.serverless/

# FuseBox cache
.fusebox/

# DynamoDB Local files
.dynamodb/

# TernJS port file
.tern-port

# Stores VSCode versions used for testing VSCode extensions
.vscode-test

# yarn v2
.yarn/cache
.yarn/unplugged
.yarn/build-state.yml
.yarn/install-state.gz
.pnp.*

# IntelliJ based IDEs
.idea

# Finder (MacOS)
.DS_Store

# Windows
Thumbs.db
ehthumbs.db
Desktop.ini

# VS Code
.vscode/

# Temporary folders
tmp/
temp/

# Build outputs
build/
dist/

# Database files
*.db
*.sqlite
*.sqlite3

# MongoDB dump files
dump/

# Redis dump files
dump.rdb

# Log files
*.log
logs/

# PM2 files
.pm2

# Docker volumes
docker-data/

# Test files
test-results/
test-reports/

# Backup files
*.bak
*.backup
*.old

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# IDEs and editors
.idea/
.vscode/
*.swp
*.swo
*~

# Temporary files
*.tmp
*.temp

# Package files
*.zip
*.tar.gz
*.rar

# Local development
.local
.cache

# API documentation
api-docs/

# SSL certificates
*.pem
*.key
*.crt
*.csr

# Secret files
secrets/
private/
```

This completes the comprehensive Node.js TypeScript backend template with all the requested features!