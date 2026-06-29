import { badRequest, internal, notFound, type ListOptions } from "@pure-auth/core";
import {
  canAccessResource,
  requireResourceAction,
  requireResourceAdministration,
  requireResourceListScope,
  type IamActor,
} from "@/access";
import type { IamPluginStorage, ResourceOrderBy } from "@/storage";
import type { CreateResourceInput, Resource, UpdateResourceInput } from "@/types";

const resourceOrderByValues = ["type", "createdAt", "updatedAt"] as const;

export type ResourceListFilter = {
  organizationId?: string;
};

export class ResourceService {
  constructor(private readonly storage: IamPluginStorage) {}

  async get(id: string, actor: IamActor): Promise<Resource> {
    const { resource } = await requireResourceAction(
      this.storage,
      id,
      "read",
      actor,
    );
    return resource;
  }

  async create(input: CreateResourceInput, actor: IamActor): Promise<Resource> {
    await requireResourceAdministration(
      this.storage,
      input.organizationId,
      actor,
    );

    if (input.type === "organization") {
      const existing = await this.storage.resources.findOrganizationResource(
        input.organizationId,
      );
      if (existing) {
        throw badRequest("Organization resource already exists");
      }
    }

    const resource = await this.storage.resources.create(input);
    if (!resource) {
      throw internal("Failed to create resource");
    }

    return resource;
  }

  async update(
    id: string,
    input: UpdateResourceInput,
    actor: IamActor,
  ): Promise<Resource> {
    const current = await this.storage.resources.findById(id);
    if (!current) {
      throw notFound("Resource not found");
    }

    await requireResourceAdministration(
      this.storage,
      current.organizationId,
      actor,
    );

    if (input.organizationId && input.organizationId !== current.organizationId) {
      await requireResourceAdministration(
        this.storage,
        input.organizationId,
        actor,
      );
    }

    const resource = await this.storage.resources.update(id, input);
    if (!resource) {
      throw notFound("Resource not found");
    }

    return resource;
  }

  async delete(id: string, actor: IamActor): Promise<void> {
    const current = await this.storage.resources.findById(id);
    if (!current) {
      throw notFound("Resource not found");
    }

    await requireResourceAdministration(
      this.storage,
      current.organizationId,
      actor,
    );

    const resource = await this.storage.resources.delete(id);
    if (!resource) {
      throw notFound("Resource not found");
    }
  }

  async list(
    options: ListOptions<ResourceOrderBy, ResourceListFilter>,
    actor: IamActor,
  ): Promise<Resource[]> {
    const organizationId = options.filter?.organizationId;
    if (!organizationId) {
      throw badRequest("Organization ID is required");
    }

    if (!resourceOrderByValues.includes(options.orderBy)) {
      throw badRequest("Invalid orderBy");
    }

    await requireResourceListScope(this.storage, organizationId, actor);

    const resources = await this.storage.resources.listByOrganizationId(
      organizationId,
      {
        ...options,
        filter: { organizationId },
      },
    );
    const allowed = await Promise.all(
      resources.map(async (resource) => ({
        resource,
        allowed: await canAccessResource(this.storage, resource, "read", actor),
      })),
    );

    return allowed
      .filter((item) => item.allowed)
      .map((item) => item.resource);
  }
}
