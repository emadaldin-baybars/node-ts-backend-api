# Node.js TypeScript Backend API Template

A production-ready backend template featuring Node.js, TypeScript, MongoDB, REST APIs, GraphQL, JWT authentication, and comprehensive middleware.

## 🚀 Features

- **Node.js** with **TypeScript** for type safety
- **MongoDB** with **Mongoose** ODM
- **JWT Authentication & Authorization** with role-based access control
- **REST APIs** with Express.js
- **GraphQL** API with Apollo Server (configured but not integrated in main app)
- **Input Validation** with Joi schemas
- **Security Middleware** (Helmet, CORS, Rate limiting)
- **Error Handling** with comprehensive error middleware
- **Logging** with Winston
- **Docker** support with multi-environment configurations
- **Clean Architecture** (Routes → Controllers → Services → Models)

## 📁 Project Structure

```
src/
├── config/
│   ├── database.ts      # MongoDB connection
│   ├── env.ts          # Environment variables
│   └── apollo.ts       # GraphQL Apollo server config
├── models/
│   ├── User.ts         # User model with Mongoose
│   └── Post.ts         # Post model with Mongoose
├── middleware/
│   ├── auth.ts         # JWT authentication & authorization
│   ├── errorHandler.ts # Global error handling
│   └── validation.ts   # Joi validation schemas
├── controllers/
│   ├── authController.ts  # Authentication endpoints
│   ├── userController.ts  # User management endpoints
│   └── postController.ts  # Post management endpoints
├── services/
│   ├── authService.ts     # Authentication business logic
│   ├── userService.ts     # User business logic
│   └── postService.ts     # Post business logic
├── routes/
│   ├── auth.ts         # Authentication routes
│   ├── users.ts        # User routes
│   └── posts.ts        # Post routes
├── types/
│   └── auth.ts         # TypeScript interfaces
├── utils/
│   ├── jwt.ts          # JWT token utilities
│   └── logger.ts       # Winston logger setup
├── graphql/            # GraphQL setup (optional)
│   ├── typeDefs/       # GraphQL type definitions
│   ├── resolvers/      # GraphQL resolvers
│   └── context.ts      # GraphQL context
├── app.ts              # Express app configuration
└── server.ts           # Server startup
```

## 🛠️ Getting Started

### Prerequisites

- Node.js (v18 or higher)
- MongoDB (local or cloud instance)
- npm or yarn

### 1. Clone the Repository

```bash
git clone https://github.com/emadaldin-baybars/node-ts-backend-api.git
cd node-ts-backend-api
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Environment Setup

Create a `.env` file in the root directory:

```bash
cp .env.example .env
```

Configure your environment variables in `.env`:

```env
NODE_ENV=development
PORT=4000

# Database
MONGODB_URI=mongodb://localhost:27017/myapp

# JWT
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRE=7d

# Bcrypt
BCRYPT_ROUNDS=12
```

### 4. Start MongoDB

Make sure MongoDB is running on your system:

```bash
# Using MongoDB service (Linux/macOS)
sudo service mongod start

# Or using Docker
docker run -d -p 27017:27017 --name mongodb mongo:7
```

### 5. Start the Development Server

```bash
npm run dev
```

The server will start at `http://localhost:4000`

## 📚 API Endpoints

### Authentication

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/auth/register` | Register new user | No |
| POST | `/api/auth/login` | Login user | No |
| GET | `/api/auth/profile` | Get user profile | Yes |

### Users (Admin only)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/users` | Get all users | Admin |
| GET | `/api/users/:id` | Get user by ID | Yes |
| PUT | `/api/users/:id` | Update user | Yes (own profile or admin) |
| DELETE | `/api/users/:id` | Delete user | Admin |

### Posts

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/posts` | Create new post | Yes |
| GET | `/api/posts` | Get all posts | No |
| GET | `/api/posts/:id` | Get post by ID | No |
| PUT | `/api/posts/:id` | Update post | Yes (author only) |
| DELETE | `/api/posts/:id` | Delete post | Yes (author only) |

### Health Check

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Server health status |

## 🔧 API Usage Examples

### Register a New User

```bash
curl -X POST http://localhost:4000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "email": "john@example.com",
    "password": "password123"
  }'
```

### Login

```bash
curl -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "password123"
  }'
```

### Create a Post (with Authentication)

```bash
curl -X POST http://localhost:4000/api/posts \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "title": "My First Post",
    "content": "This is the content of my post",
    "tags": ["nodejs", "api"],
    "isPublished": true
  }'
```

### Get All Posts

```bash
curl http://localhost:4000/api/posts
```

## 🐳 Docker Support

### Development with Docker Compose

```bash
# Start development environment
docker-compose -f docker-compose.dev.yml up

# Or using npm script
npm run docker:dev
```

### Production Build

```bash
# Build Docker image
docker build -t node-ts-backend-api .

# Or using npm script
npm run docker:build
```

## 🧪 Testing

```bash
# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

## 📝 Available Scripts

```bash
npm run dev          # Start development server with nodemon
npm run build        # Build TypeScript to JavaScript
npm run start        # Start production server
npm run lint         # Run ESLint
npm run test         # Run Jest tests
npm run docker:dev   # Start with Docker Compose (development)
npm run docker:prod  # Start with Docker Compose (production)
```

## 🔒 Security Features

- **JWT Authentication** with configurable expiration
- **Password Hashing** with bcrypt
- **Rate Limiting** to prevent abuse
- **CORS** configuration
- **Helmet** for security headers
- **Input Validation** with Joi schemas
- **Error Handling** without exposing sensitive information

## 📊 Data Models

### User Model

```typescript
interface IUser {
  username: string;
  email: string;
  password: string;
  role: 'user' | 'admin';
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}
```

### Post Model

```typescript
interface IPost {
  title: string;
  content: string;
  author: ObjectId;
  tags: string[];
  isPublished: boolean;
  publishedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}
```

## 🚀 Deployment

### Environment Variables for Production

```env
NODE_ENV=production
PORT=4000
MONGODB_URI=mongodb://your-production-db-url
JWT_SECRET=your-very-secure-production-secret
JWT_EXPIRE=7d
BCRYPT_ROUNDS=12
```

### Production Deployment Steps

1. **Build the application:**
   ```bash
   npm run build
   ```

2. **Set environment variables**

3. **Start the production server:**
   ```bash
   npm start
   ```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the ISC License.

## 🔧 Customization

### Adding New Routes

1. Create a new controller in `src/controllers/`
2. Create a new service in `src/services/`
3. Create a new route file in `src/routes/`
4. Add the route to `src/app.ts`

### Adding New Models

1. Create a new model in `src/models/`
2. Define the interface and schema
3. Export the model for use in services

### Adding Validation

1. Add new Joi schemas in `src/middleware/validation.ts`
2. Use the `validateBody` middleware in your routes

## 🐛 Troubleshooting

### Common Issues

1. **MongoDB Connection Error**: Ensure MongoDB is running and the connection string is correct
2. **JWT Token Issues**: Check if JWT_SECRET is set in environment variables
3. **Port Already in Use**: Change the PORT in your `.env` file
4. **TypeScript Compilation Errors**: Run `npm run build` to check for type errors

### Debug Mode

Set `NODE_ENV=development` in your `.env` file to enable:
- Detailed error messages
- Console logging
- Development-specific configurations

## 📞 Support

If you encounter any issues or have questions, please:
1. Check the troubleshooting section
2. Search existing issues on GitHub
3. Create a new issue with detailed information

---

**Happy coding! 🎉**
