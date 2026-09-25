import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as fs from 'fs';
import * as path from 'path';
import { execFileSync } from 'child_process';

/**
 * True when asset bundling is being skipped (test/CI environments with no
 * Docker and no network for pip3).
 */
const skipBundling = (): boolean => !!process.env.SKIP_BUNDLING;

/**
 * Builds the bundling options for a Python Lambda asset.
 *
 * A newer boto3/botocore is bundled into each function (see lambda/*\/requirements.txt)
 * so the `devops-agent` client is present regardless of the runtime's baked-in SDK.
 * Prefers local bundling (host pip3, no Docker); falls back to the Docker image.
 *
 * WHY execFileSync and fs.cpSync rather than a shell: `assetDir` and `outputDir`
 * are directory paths, and a shell would re-parse them, so a path containing a
 * space or a shell metacharacter would either break the build or run as a
 * command. Passing argv entries directly means no shell ever sees them, and
 * copying in-process removes the second command entirely. Nothing external
 * reaches either argument today — both call sites derive from __dirname — but
 * this is sample code, so the pattern it demonstrates should be the safe one.
 */
export const makeBundling = (assetDir: string): cdk.BundlingOptions => ({
  image: lambda.Runtime.PYTHON_3_12.bundlingImage,
  command: [
    'bash', '-c',
    'pip install -r requirements.txt -t /asset-output && cp -au . /asset-output',
  ],
  local: {
    tryBundle(outputDir: string): boolean {
      // In test/CI environments without Docker or network access,
      // skip bundling entirely — we're validating infrastructure, not packaging.
      if (skipBundling()) {
        fs.writeFileSync(
          path.join(outputDir, 'handler.py'),
          '# placeholder for test bundling',
        );
        return true;
      }
      try {
        execFileSync('pip3', ['--version'], { stdio: 'ignore' });
      } catch {
        return false; // no local pip -> let CDK fall back to Docker
      }
      execFileSync(
        'pip3',
        ['install', '-r', path.join(assetDir, 'requirements.txt'), '-t', outputDir],
        { stdio: 'inherit' }
      );
      // Equivalent to `cp -a ${assetDir}/. ${outputDir}`: copy the source
      // contents in over the installed dependencies. Throws on failure, so a
      // partial bundle never reaches the function.
      fs.cpSync(assetDir, outputDir, { recursive: true });
      return true;
    },
  },
});

/**
 * Full asset options (bundling + hash policy) for a Python Lambda asset.
 *
 * WHY the explicit assetHash under SKIP_BUNDLING: by default CDK derives the
 * asset hash from the SOURCE directory and the bundling options — neither of
 * which mentions SKIP_BUNDLING. A skipped (placeholder) bundle therefore lands
 * in the SAME `cdk.out/asset.<hash>/` directory a real bundle would, and CDK
 * skips bundling whenever that directory already exists. Net effect: run the
 * test suite (which sets SKIP_BUNDLING), then deploy from the same working
 * tree, and CDK silently ships a 31-byte placeholder handler instead of the
 * real function — no error at synth or deploy time, only an ImportError at
 * invocation. Pinning a distinct custom hash for the placeholder keeps the two
 * artifacts in separate directories, so a real deploy always re-bundles.
 */
export interface PythonAssetOptions {
  readonly bundling: cdk.BundlingOptions;
  /** Set only when bundling is skipped, to keep the placeholder hash distinct. */
  readonly assetHash?: string;
}

export const makeAssetOptions = (assetDir: string): PythonAssetOptions => ({
  bundling: makeBundling(assetDir),
  ...(skipBundling()
    ? { assetHash: `skip-bundling-placeholder-${path.basename(assetDir)}` }
    : {}),
});
