import unittest


# System Under Test (SUT)
def add(a: float, b: float) -> float:
    return a + b


def divide(a: float, b: float) -> float:
    if b == 0:
        raise ValueError("Cannot divide by zero.")
    return a / b


class User:

    def __init__(self, username: str, role: str = "user"):
        self.username = username
        self.role = role
        self.is_active = True

    def deactivate(self):
        self.is_active = False


# Test Suite
class TestApplication(unittest.TestCase):

    def setUp(self):
        """Runs before every individual test method."""
        self.sample_user = User("test_user", role="admin")

    def tearDown(self):
        """Runs after every individual test method."""
        self.sample_user = None

    # --- Math Tests ---
    def test_add_success(self):
        """Test standard addition."""
        self.assertEqual(add(2, 3), 5)
        self.assertEqual(add(-1, 1), 0)

    def test_divide_success(self):
        """Test standard division."""
        self.assertAlmostEqual(divide(10, 3), 3.33333333, places=5)

    def test_divide_by_zero_raises_error(self):
        """Test that dividing by zero raises a ValueError."""
        with self.assertRaises(ValueError) as context:
            divide(5, 0)
        self.assertEqual(str(context.exception), "Cannot divide by zero.")

    # --- Object State Tests ---
    def test_user_initialization(self):
        """Test default object creation parameters."""
        self.assertEqual(self.sample_user.username, "test_user")
        self.assertEqual(self.sample_user.role, "admin")
        self.assertTrue(self.sample_user.is_active)

    def test_user_deactivation(self):
        """Test modifying object state."""
        self.sample_user.deactivate()
        self.assertFalse(self.sample_user.is_active)


if __name__ == "__main__":
    # Run tests directly from command line: python test_script.py
    unittest.main(verbosity=2)