import type { User } from '@/app/lib/definitions';
import { sql } from '@vercel/postgres';
import bcrypt from 'bcrypt';
import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import GithubProvider from 'next-auth/providers/github';
import GoogleProvider from 'next-auth/providers/google';
import { z } from 'zod';
import { authConfig } from './auth.config';

async function getUser(email: string): Promise<User | undefined> {
	try {
		const user = await sql<User>`SELECT * from USERS where email=${email}`;
		return user.rows[0];
	} catch (error) {
		console.error('Failed to fetch user:', error);
		throw new Error('Failed to fetch user.');
	}
}

export const {
	auth,
	handlers: { GET, POST },
	signIn,
	signOut,
} = NextAuth({
	...authConfig,
	providers: [
		Credentials({
			name: 'E-mail',
			// `credentials` is used to generate a form on the sign in page.
			// You can specify which fields should be submitted, by adding keys to the `credentials` object.
			// e.g. domain, username, password, 2FA token, etc.
			// You can pass any HTML attribute to the <input> tag through the object.
			credentials: {
				email: {
					label: 'E-mail',
					type: 'email',
					placeholder: 'example@example.com',
				},
				password: { label: 'Password', type: 'password' },
			},
			async authorize(credentials) {
				const parsedCredentials = z
					.object({ email: z.string().email(), password: z.string().min(6) })
					.safeParse(credentials);

				if (parsedCredentials.success) {
					const { email, password } = parsedCredentials.data;
					const user = await getUser(email);
					if (!user) return null;
					const passwordsMatch = await bcrypt.compare(password, user.password);
					if (passwordsMatch) return user;
				}
				console.log('Invalid credentials');
				return null;
			},
		}),
		GoogleProvider({
			clientId: process.env.GOOGLE_ID as string,
			clientSecret: process.env.GOOGLE_SECRET as string,
		}),
		GithubProvider({
			clientId: process.env.GITHUB_ID as string,
			clientSecret: process.env.GITHUB_SECRET as string,
		}),
	],
});
