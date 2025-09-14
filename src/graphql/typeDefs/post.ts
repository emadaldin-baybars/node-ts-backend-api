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
