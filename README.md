# CRT-based-Secret-Sharing-and-its-Applications
The project focuses on understanding CRT-based secret sharing (SS) and implementing applications where this type of SS has a pivotal role. In particular, it studied the performance of the weighted encryption schemes when they are implemented using CRT-SS

## Installation
Clone the repository and unzip it to your personal computer.
Use the package manager to install the package.

```bash
pip install .
```

To get the required dependencies run the following command.

```bash
pip install -r requirements.txt
```

## Usage

```python
import unittest
from crt_secret_sharing.crt_ss import share_distribution, share_reconstruction

class TestWithUnweightedSecretSharing(unittest.TestCase):

    def test_simple_success(self):
        _, shares, p_0, p_i = share_distribution(128, 3, 2, 420420, None, None, None, False)
        test_number = 2
        shares_subset = shares[:test_number]
        primes_subset = p_i[:test_number]
        secret = share_reconstruction(p_0, primes_subset, shares_subset)
        self.assertEqual(secret, 420420)
```

