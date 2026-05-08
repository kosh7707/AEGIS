import { useState, useEffect, useCallback } from "react";
import type { BuildTarget, BuildProfile } from "@aegis/shared";
import {
  fetchBuildTargets,
  createBuildTarget,
  updateBuildTarget,
  deleteBuildTarget,
  discoverBuildTargets,
  logError,
} from "@/common/api/client";
import type { DiscoverBuildTargetsResult } from "@/common/api/pipeline";

export function useBuildTargets(projectId?: string) {
  const [targets, setTargets] = useState<BuildTarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [discovering, setDiscovering] = useState(false);

  const load = useCallback(async () => {
    if (!projectId) return;
    setLoading(true);
    try {
      const data = await fetchBuildTargets(projectId);
      setTargets(data);
    } catch (e) {
      logError("Load build targets", e);
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => { load(); }, [load]);

  const add = useCallback(async (
    name: string,
    relativePath: string,
    buildProfile?: BuildProfile,
    buildSystem?: string,
    includedPaths?: string[],
    scriptHintPath?: string,
  ) => {
    if (!projectId) return;
    const created = await createBuildTarget(projectId, {
      name,
      relativePath,
      buildProfile,
      ...(buildSystem !== undefined ? { buildSystem } : {}),
      includedPaths,
      ...(scriptHintPath !== undefined && scriptHintPath !== "" ? { scriptHintPath } : {}),
    });
    setTargets((prev) => [...prev, created]);
    return created;
  }, [projectId]);

  const update = useCallback(async (
    targetId: string,
    body: {
      name?: string;
      relativePath?: string;
      buildProfile?: BuildProfile;
      includedPaths?: string[];
      scriptHintPath?: string | null;
    },
  ) => {
    if (!projectId) return;
    if (body.includedPaths !== undefined) {
      throw new Error("includedPaths edits unsupported by S2 contract; use BuildTarget recreate flow.");
    }
    const { includedPaths: _ignoredIncludedPaths, ...supportedBody } = body;
    const updated = await updateBuildTarget(projectId, targetId, supportedBody);
    setTargets((prev) => prev.map((t) => (t.id === targetId ? updated : t)));
    return updated;
  }, [projectId]);

  const remove = useCallback(async (targetId: string) => {
    if (!projectId) return;
    await deleteBuildTarget(projectId, targetId);
    setTargets((prev) => prev.filter((t) => t.id !== targetId));
  }, [projectId]);

  const discover = useCallback(async (): Promise<DiscoverBuildTargetsResult | undefined> => {
    if (!projectId) return undefined;
    setDiscovering(true);
    try {
      const result = await discoverBuildTargets(projectId);
      setTargets(result.targets);
      return result;
    } catch (e) {
      logError("Discover targets", e);
      throw e;
    } finally {
      setDiscovering(false);
    }
  }, [projectId]);

  return { targets, loading, discovering, load, add, update, remove, discover };
}
