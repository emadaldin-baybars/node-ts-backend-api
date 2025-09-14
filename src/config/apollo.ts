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