import axios, { AxiosResponse } from 'axios';
import dayjs from 'dayjs';
import { request } from '@utils/request';
import { getRoute } from '@utils/route';
import { NextApiRequest, NextApiResponse } from 'next';
import NextAuth, { Session, User } from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import {
  INVALID_RESPONSE_ERROR,
  REFRESH_TOKEN_REJECTED_ERROR,
  REJECTED_AUTHENTICATION_ERROR,
} from '@constants/error';
import { JWT } from 'next-auth/jwt';

function prepareHeaders(headers?: Record<string, string>) {
  if (!headers) {
    return;
  }
  return {
    cookie: headers.cookie,
    'accept-encoding': headers['accept-encoding'],
    'accept-language': headers['accept-language'],
    'user-agent': headers['user-agent'],
  };
}

const AUTHENTICATION_METHODS = {
  REVOKE_TOKEN: {
    key: 'revokeToken',
    credentials: {
      table: { type: 'text' },
      token: { type: 'text' },
      token_type_hint: { type: 'text' },
    },
    endpoint: '/oauth/revoke',
  },
};

const handleRefreshToken = async (refreshToken: string, scope: string) => {
  try {
    const res: AxiosResponse = await request({
      url: AUTHENTICATION_METHODS.EMAIL.endpoint,
      method: 'POST',
      data: {
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: `${process.env.APP_CLIENT_ID}`,
        client_secret: `${process.env.APP_CLIENT_SECRET}`,
        scope: scope,
      },
    });
    if (res.data?.access_token) {
      const tokenInfo = res.data;
      return {
        id: tokenInfo.resource_id,
        accessToken: tokenInfo.access_token,
        refreshToken: tokenInfo.refresh_token,
        tokenType: tokenInfo.token_type,
        expiresIn: tokenInfo.expires_in,
        createdAt: tokenInfo.created_at,
        authenticatedOwner: tokenInfo.resource_owner,
        authenticatedId: tokenInfo.resource_id,
        scope: tokenInfo.scope,
      };
    }
    throw new Error(INVALID_RESPONSE_ERROR);
  } catch (error: unknown) {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      return {
        id: '',
        error: REFRESH_TOKEN_REJECTED_ERROR,
      };
    }
    return {
      id: '',
      error: (error as { message: string })?.message,
    };
  }
};

const prepareAuthenticationFormData = (table: string) => {
  const data = new URLSearchParams();
  data.append('grant_type', 'password');
  data.append('client_id', `${process.env.APP_CLIENT_ID}`);
  data.append('client_secret', `${process.env.APP_CLIENT_SECRET}`);
  data.append('scope', table);

  return data;
};

type AuthenticationResponse = {
  access_token: string;
  refresh_token?: string;
  resource_owner: string;
  resource_id: number | string;
  token_type: string;
  expires_in?: number;
  created_at: number;
  scope: string;
};
const parseAuthenticationInfo = (res: AuthenticationResponse) => {
  return {
    id: `${res.resource_id}`,
    accessToken: res.access_token,
    refreshToken: res.refresh_token,
    authenticatedOwner: res.resource_owner,
    authenticatedId: res.resource_id,
    tokenType: res.token_type,
    expiresIn: res.expires_in,
    scope: res.scope,
    createdAt: res.created_at,
  };
};

const providers = [
  CredentialsProvider({
    id: 'testVerify',
    authorize: async () => {
      if (process.env.NODE_ENV !== 'development') {
        throw new Error(REJECTED_AUTHENTICATION_ERROR);
      }
      return {
        id: '1',
        authenticatedOwner: 'User',
        authenticatedId: 1,
        accessToken: '__THIS_IS_TOKEN__',
        refreshToken: '__THIS_IS_REFRESH_TOKEN__',
        expiresIn: 200,
        tokenType: 'Bearer',
        createdAt: Date.now() / 1000,
      };
    },
    credentials: { phone: { type: 'text' } },
  }),
];

const options = {
  pages: {
    signIn: '/',
    signOut: '/',
    error: '/',
    verifyRequest: '/',
    newUser: '/',
  },
  providers,
  callbacks: {
    async session({ session, token }: { token?: JWT; session: Session }): Promise<Session> {
      if (!token?.accessToken) {
        return session;
      }
      return {
        ...session,
        // Real refresh token do not need to reponse to client
        user: {
          authenticatedOwner: token.authenticatedOwner,
          authenticatedId: token.authenticatedId,
          accessToken: token.accessToken,
          expiresIn: token.expiresIn,
          error: token.error,
          scope: token.scope,
          tokenType: token.tokenType,
        },
      };
    },
    async jwt({ token, user }: { token: JWT; user?: User }): Promise<JWT> {
      // Initial when user just logged
      if (user && user.accessToken) {
        return {
          accessToken: user.accessToken,
          refreshToken: user.refreshToken,
          authenticatedOwner: user.authenticatedOwner,
          authenticatedId: user.authenticatedId,
          tokenType: user.tokenType,
          expiresIn: user.expiresIn,
          accessTokenExpireAt: dayjs(user.createdAt)
            .add(+(user.expiresIn || 0), 's')
            .unix(),
          scope: user.scope,
        };
      }
      // https://next-auth.js.org/tutorials/refresh-token-rotation
      // NOTICE: Currently we refresh token everytime user load the new page
      if (
        !token.refreshToken ||
        dayjs()
          .add(+(process.env.NEXT_PUBLIC_ACCESS_TOKEN_THRESHOLD || 0) / 1000, 's')
          .isBefore(dayjs(token.accessTokenExpireAt))
      ) {
        return token;
      }
      const result = await handleRefreshToken(token.refreshToken, `${token.authenticatedOwner}`);
      if (!result?.accessToken || result.error) {
        return {
          ...token,
          error: result.error,
        };
      }
      return {
        authenticatedId: token.authenticatedId,
        authenticatedOwner: token.authenticatedOwner,
        tokenType: result.tokenType,
        expiresIn: result.expiresIn,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken || '',
        accessTokenExpireAt: dayjs(result.createdAt).add(result.expiresIn, 's').unix(),
        scope: result.scope,
      };
    },
  },
};

export default (req: NextApiRequest, res: NextApiResponse) => NextAuth(req, res, options);
