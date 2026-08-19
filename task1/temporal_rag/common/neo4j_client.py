import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
import neo4j
from neo4j import GraphDatabase, Driver, Session
from neo4j.exceptions import (
    ServiceUnavailable,
    SessionExpired,
    TransientError,
    Neo4jError,
)

from config.settings import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
from common.logging_utils import setup_logger

logger = setup_logger("neo4j_client", "neo4j.log")


class Neo4jClient:
    """
    Thread-safe Neo4j driver wrapper with retry logic, context management,
    and batch execution capabilities.
    """

    def __init__(
        self,
        uri: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        max_connection_lifetime: int = 3600,
        max_connection_pool_size: int = 50,
        connection_acquisition_timeout: float = 60.0,
    ):
        self.uri = uri or NEO4J_URI
        self.user = user or NEO4J_USER
        self.password = password or NEO4J_PASSWORD
        self._driver: Optional[Driver] = None
        self.max_connection_lifetime = max_connection_lifetime
        self.max_connection_pool_size = max_connection_pool_size
        self.connection_acquisition_timeout = connection_acquisition_timeout

    def connect(self) -> Driver:
        """Initializes and returns the Neo4j driver."""
        if self._driver is None:
            logger.info(f"Connecting to Neo4j at {self.uri} (user: {self.user})")
            auth = (self.user, self.password) if self.user and self.password else None
            self._driver = GraphDatabase.driver(
                self.uri,
                auth=auth,
                max_connection_lifetime=self.max_connection_lifetime,
                max_connection_pool_size=self.max_connection_pool_size,
                connection_acquisition_timeout=self.connection_acquisition_timeout,
            )
        return self._driver

    def close(self):
        """Closes the driver connection pool."""
        if self._driver is not None:
            logger.info("Closing Neo4j driver connection")
            self._driver.close()
            self._driver = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def verify_connectivity(self) -> bool:
        """Checks if the Neo4j instance is reachable and authenticated."""
        try:
            driver = self.connect()
            driver.verify_connectivity()
            logger.info("Successfully verified Neo4j connectivity.")
            return True
        except Exception as e:
            logger.error(f"Neo4j connectivity check failed: {e}")
            return False

    def execute_query(
        self,
        query: str,
        parameters: Optional[Dict[str, Any]] = None,
        database: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Executes a Cypher query with automatic retries on transient errors.
        Returns the result records as a list of dictionaries.
        """
        driver = self.connect()
        retries = 3
        backoff = 1.0

        for attempt in range(1, retries + 1):
            try:
                with driver.session(database=database) as session:
                    result = session.run(query, parameters or {})
                    return [record.data() for record in result]
            except (ServiceUnavailable, SessionExpired, TransientError) as e:
                logger.warning(
                    f"Neo4j transient error on attempt {attempt}/{retries}: {e}. Retrying in {backoff:.1f}s..."
                )
                if attempt == retries:
                    logger.error(f"Neo4j query failed after {retries} attempts.")
                    raise
                time.sleep(backoff)
                backoff *= 2.0
            except Exception as e:
                logger.error(f"Neo4j non-transient error executing query: {e}")
                raise

    def execute_write_transaction(
        self,
        transaction_func: Callable[[Any], Any],
        database: Optional[str] = None,
        **kwargs,
    ) -> Any:
        """
        Executes a function inside a managed write transaction with automatic retries.
        """
        driver = self.connect()
        with driver.session(database=database) as session:
            return session.execute_write(transaction_func, **kwargs)

    def apply_schema(self, cql_filepath: Path | str, database: Optional[str] = None) -> List[str]:
        """
        Parses and applies Cypher constraints and indexes from a .cql file.
        """
        cql_path = Path(cql_filepath)
        if not cql_path.exists():
            raise FileNotFoundError(f"Schema file not found: {cql_path}")

        raw_cql = cql_path.read_text(encoding="utf-8")
        # Split statements by semicolon, skipping comments and empty lines
        statements = []
        for stmt in raw_cql.split(";"):
            cleaned = "\n".join(
                line for line in stmt.splitlines() if not line.strip().startswith("//")
            ).strip()
            if cleaned:
                statements.append(cleaned)

        results = []
        logger.info(f"Applying {len(statements)} schema statements from {cql_path.name}")
        for stmt in statements:
            try:
                self.execute_query(stmt, database=database)
                results.append(f"SUCCESS: {stmt[:60]}...")
                logger.info(f"Schema applied: {stmt[:60]}...")
            except Exception as e:
                # If constraint/index already exists, log as info/warning rather than breaking
                logger.warning(f"Schema statement warning/error on '{stmt[:60]}...': {e}")
                results.append(f"WARNING: {e}")

        return results
