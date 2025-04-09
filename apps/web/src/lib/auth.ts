
import CredentialsProvider from "next-auth/providers/credentials";
import { z } from "zod";
import bcrypt from "bcrypt";
import db from "@repo/db/client";
import { NextAuthOptions } from "next-auth";




const signUpBody = z.object({
    phone: z.string().min(10, "The number should be must be of 10 digits"),
    password: z.string().min(8, "Password must be of 8 characters")
})

export const authOptions = {
    providers: [
        CredentialsProvider({
            name: 'Credentials',
            credentials: {
                phone: { label: "Phone number", type: "text", placeholder: "123123", required: true },
                password: { label: "password", type: "password", required: true }
            },

            async authorize(credentials: any) {
                const parsedSigninbody = signUpBody.safeParse(credentials);

                if (!parsedSigninbody.success) {
                    throw new Error(`Send proper phone no and password with atleast 8 char`)
                }

                if (!credentials.phone) {
                    return null
                }

                const hashedPassword = await bcrypt.hash(credentials.password, 10);
                const existingUser = await db.user.findfirst({
                    where: {
                        number: credentials.phone
                    }
                });

                if (existingUser) {
                    const passwordValidation = await bcrypt.compare(credentials.password, existingUser.password);
                    if (!passwordValidation) {
                        throw new Error("Incorrect Password");
                    }
                    if (passwordValidation) {
                        return {
                            id: existingUser.id.toString(),
                            name: existingUser.name,
                            email: existingUser.number
                        }
                    }
                    return null;
                }


                try {
                    const user = await db.user.create({
                        data: {
                            number: credentials.phone,
                            password: hashedPassword,
                            Balance: {
                                create: {
                                    amount: 10000 * 100,
                                    locked: 0
                                }
                            }
                        }
                    });

                    return {
                        id: user.id.toString(),
                        name: user.name,
                        email: user.number
                    }
                } catch (e) {
                    console.error(e);
                }
                return null

            },
        })
    ],

    secret:process.env.JWT_SECRET || "secret",
    pages:{
        signIn:"/signin"
    },
    callbacks:{
        async session({token,session}:{token:any,session:any}){
            session.user.id=token.sub;
            return session;
        }
    }

}satisfies NextAuthOptions; 


