import {
  badRequest,
  getBearerToken,
  getHeader,
  notFound,
  unauthorized,
  type ActorResolver,
  type HeadersLike,
  type ServiceContext,
} from "@pure-auth/core";
import { requireOrganizationMembership } from "@pure-auth/plugin-organization";
import type { IamPluginStorage } from "@/storage";
import type { ApiKey, ApiKeyActor, CreateApiKeyInput, PublicApiKey } from "@/types";

export type ApiKeyServiceOptions = {
  secretPrefix?: string;
};

export type CreateApiKeyResult = {
  apiKey: PublicApiKey;
  secret: string;
};

export type RotateApiKeyResult = CreateApiKeyResult;

const API_KEY_PARTS = 3;

export class ApiKeyService {
  private readonly secretPrefix: string;

  constructor(
    private readonly storage: IamPluginStorage,
    options: ApiKeyServiceOptions = {},
  ) {
    this.secretPrefix = options.secretPrefix ?? "lp";
  }

  actorResolver(): ActorResolver {
    return async ({ headers, bearerToken }) => {
      const headerSecret = getHeader(headers, "x-api-key");
      const secret =
        headerSecret ??
        (bearerToken?.startsWith(`${this.secretPrefix}_`) ? bearerToken : null);

      if (!secret) {
        return null;
      }

      return this.verifySecret(secret);
    };
  }

  async create(
    input: CreateApiKeyInput,
    context: ServiceContext,
  ): Promise<CreateApiKeyResult> {
    await requireOrganizationMembership(
      this.storage,
      input.organizationId,
      context.userId,
      ["owner", "admin"],
    );

    if (input.expiresAt && input.expiresAt <= new Date()) {
      throw badRequest("API key expiration must be in the future");
    }

    if (input.roleId) {
      const role = await this.storage.roles.findById(input.roleId);
      if (!role || role.organizationId !== input.organizationId) {
        throw badRequest("API key role must belong to the organization");
      }
    }

    const secret = this.generateSecret();
    const apiKey = await this.storage.apiKeys.create({
      ...input,
      prefix: this.getPrefix(secret),
      secretHash: await this.hashSecret(secret),
      roleId: input.roleId ?? null,
      expiresAt: input.expiresAt ?? null,
      createdByUserId: context.userId,
    });

    if (!apiKey) {
      throw notFound("Failed to create API key");
    }

    return { apiKey: this.toPublicApiKey(apiKey), secret };
  }

  async list(
    organizationId: string,
    options: { limit: number; offset: number },
    context: ServiceContext,
  ): Promise<PublicApiKey[]> {
    await requireOrganizationMembership(
      this.storage,
      organizationId,
      context.userId,
      ["owner", "admin"],
    );

    const apiKeys = await this.storage.apiKeys.listByOrganizationId(
      organizationId,
      options,
    );
    return apiKeys.map((apiKey) => this.toPublicApiKey(apiKey));
  }

  async revoke(id: string, context: ServiceContext): Promise<void> {
    const apiKey = await this.requireManagedApiKey(id, context);
    const revoked = await this.storage.apiKeys.revoke(apiKey.id);

    if (!revoked) {
      throw notFound("API key not found");
    }
  }

  async rotate(
    id: string,
    context: ServiceContext,
  ): Promise<RotateApiKeyResult> {
    const apiKey = await this.requireManagedApiKey(id, context);
    const secret = this.generateSecret();
    const rotated = await this.storage.apiKeys.rotateSecret(id, {
      prefix: this.getPrefix(secret),
      secretHash: await this.hashSecret(secret),
    });

    if (!rotated) {
      throw notFound("API key not found");
    }

    return { apiKey: this.toPublicApiKey(rotated), secret };
  }

  async verifySecret(secret: string): Promise<ApiKeyActor> {
    const prefix = this.getPrefix(secret);
    const apiKey = await this.storage.apiKeys.findByPrefix(prefix);

    if (
      !apiKey ||
      apiKey.revokedAt ||
      (apiKey.expiresAt && apiKey.expiresAt <= new Date())
    ) {
      throw unauthorized("Invalid API key");
    }

    if (!(await this.secretsMatch(secret, apiKey.secretHash))) {
      throw unauthorized("Invalid API key");
    }

    if (apiKey.roleId) {
      const role = await this.storage.roles.findById(apiKey.roleId);
      if (!role || role.organizationId !== apiKey.organizationId) {
        throw unauthorized("Invalid API key role");
      }
    }

    await this.storage.apiKeys.markUsed(apiKey.id);

    return {
      type: "apiKey",
      apiKey: this.toPublicApiKey(apiKey),
      organizationId: apiKey.organizationId,
      roleId: apiKey.roleId ?? null,
    };
  }

  readSecretFromHeaders(headers: HeadersLike): string | null {
    return getHeader(headers, "x-api-key") ?? getBearerToken(headers);
  }

  private async requireManagedApiKey(
    id: string,
    context: ServiceContext,
  ): Promise<ApiKey> {
    const apiKey = await this.storage.apiKeys.findById(id);
    if (!apiKey) {
      throw notFound("API key not found");
    }

    await requireOrganizationMembership(
      this.storage,
      apiKey.organizationId,
      context.userId,
      ["owner", "admin"],
    );

    return apiKey;
  }

  private generateSecret(): string {
    return `${this.secretPrefix}_${randomUrlSafe(8)}_${randomUrlSafe(32)}`;
  }

  private getPrefix(secret: string): string {
    const parts = secret.split("_");
    if (
      parts.length !== API_KEY_PARTS ||
      parts[0] !== this.secretPrefix ||
      !parts[1]
    ) {
      throw unauthorized("Invalid API key");
    }

    return parts[1];
  }

  private async hashSecret(secret: string): Promise<string> {
    const bytes = new TextEncoder().encode(secret);
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return toHex(new Uint8Array(digest));
  }

  private async secretsMatch(secret: string, expectedHash: string): Promise<boolean> {
    const actualHash = await this.hashSecret(secret);
    if (actualHash.length !== expectedHash.length) {
      return false;
    }

    let diff = 0;
    for (let index = 0; index < actualHash.length; index += 1) {
      diff |= actualHash.charCodeAt(index) ^ expectedHash.charCodeAt(index);
    }

    return diff === 0;
  }

  private toPublicApiKey(apiKey: ApiKey): PublicApiKey {
    const { secretHash: _secretHash, ...publicApiKey } = apiKey;
    return publicApiKey;
  }
}

function randomUrlSafe(size: number): string {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function toHex(bytes: Uint8Array): string {
  return [...bytes]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
