import httpx
import logging
import base64
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class GitHubClient:
    def __init__(self, token: str):
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3+json"
        }
        self.base_url = "https://api.github.com"

    def _parse_repo_url(self, repo_url: str) -> Optional[str]:
        """
        Extracts owner/repo from https://github.com/owner/repo
        """
        try:
            parsed = urlparse(repo_url)
            path_parts = parsed.path.strip('/').split('/')
            if len(path_parts) >= 2:
                return f"{path_parts[0]}/{path_parts[1]}"
            return None
        except Exception as e:
            logger.error(f"Failed to parse repo URL {repo_url}: {e}")
            return None

    async def get_repo_tree(self, repo_url: str, branch: str = "main") -> List[str]:
        """
        Fetches the recursive tree of the repository to get all file paths.
        Returns a list of file paths.
        """
        repo_path = self._parse_repo_url(repo_url)
        if not repo_path:
            raise ValueError(f"Invalid GitHub repository URL: {repo_url}")

        # First, get the commit SHA for the branch to get the tree SHA
        commits_url = f"{self.base_url}/repos/{repo_path}/commits/{branch}"
        async with httpx.AsyncClient() as client:
            try:
                commit_resp = await client.get(commits_url, headers=self.headers, timeout=10.0)
                commit_resp.raise_for_status()
                tree_sha = commit_resp.json()["commit"]["tree"]["sha"]

                # Now get the recursive tree
                tree_url = f"{self.base_url}/repos/{repo_path}/git/trees/{tree_sha}?recursive=1"
                tree_resp = await client.get(tree_url, headers=self.headers, timeout=15.0)
                tree_resp.raise_for_status()

                tree_data = tree_resp.json()
                file_paths = []
                for item in tree_data.get("tree", []):
                    if item["type"] == "blob": # Only files, not directories
                        file_paths.append(item["path"])
                
                return file_paths
            except httpx.HTTPError as e:
                logger.error(f"GitHub API error fetching tree for {repo_path}: {e}")
                raise Exception(f"Failed to fetch repository structure: {e}")

    async def get_file_content(self, repo_url: str, file_path: str, branch: str = "main") -> str:
        """
        Fetches the content of a specific file.
        """
        repo_path = self._parse_repo_url(repo_url)
        if not repo_path:
            raise ValueError(f"Invalid GitHub repository URL: {repo_url}")

        # We can use the raw URL or the contents API
        content_url = f"{self.base_url}/repos/{repo_path}/contents/{file_path}?ref={branch}"
        
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(content_url, headers=self.headers, timeout=10.0)
                resp.raise_for_status()
                data = resp.json()
                
                if "content" in data and data.get("encoding") == "base64":
                    decoded_content = base64.b64decode(data["content"]).decode('utf-8', errors='replace')
                    return decoded_content
                return ""
            except httpx.HTTPError as e:
                logger.error(f"GitHub API error fetching file {file_path}: {e}")
                return "" # Return empty if file cannot be read, agent will just skip it
