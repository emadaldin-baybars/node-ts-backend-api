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
