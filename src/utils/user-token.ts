export interface JWTClaims {
  iss: string;
  sub: string;
  aud?: string;
  scope?: string;
  email: string;
  email_verified: boolean;
  exp: number;
  iat?: number;
  nonce?: string;
  family_name?: string;
  given_name: string;
  name: string;
  picture?: string;
}
