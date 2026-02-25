import io
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import app as sales_app


class PaymentWorkflowTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        sales_app.DATABASE_PATH = os.path.join(self.tmpdir.name, "test.db")
        sales_app.PAYMENT_PROOF_FOLDER = os.path.join(self.tmpdir.name, "payment_proofs")
        sales_app.INVOICE_FOLDER = os.path.join(self.tmpdir.name, "invoices")
        os.makedirs(sales_app.PAYMENT_PROOF_FOLDER, exist_ok=True)
        os.makedirs(sales_app.INVOICE_FOLDER, exist_ok=True)
        sales_app.app.config["TESTING"] = True
        sales_app.init_db()

        conn = sqlite3.connect(sales_app.DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO products (name, price, stock, image) VALUES (?, ?, ?, ?)",
            ("Widget", 100.0, 10, "sample.jpg"),
        )
        cursor.execute(
            """
            INSERT INTO orders (username, product_id, quantity, order_status, estimated_delivery, payment_status)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("customer", 1, 2, "pending", "2026-01-01", "unpaid"),
        )
        cursor.execute("UPDATE products SET stock = stock - 2 WHERE id = 1")
        conn.commit()
        conn.close()

        self.client = sales_app.app.test_client()

    def tearDown(self):
        self.tmpdir.cleanup()

    def _login_as(self, username, role):
        with self.client.session_transaction() as sess:
            sess["username"] = username
            sess["role"] = role

    def test_upload_payment_proof_sets_pending(self):
        self._login_as("customer", "Customer")
        response = self.client.post(
            "/orders/1/upload-payment-proof",
            data={"payment_proof": (io.BytesIO(b"proof"), "proof.png")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)

        conn = sqlite3.connect(sales_app.DATABASE_PATH)
        row = conn.execute("SELECT payment_status, payment_proof_url FROM orders WHERE id=1").fetchone()
        conn.close()

        self.assertEqual(row[0], "pending")
        self.assertTrue(row[1])

    @patch("app.send_email_notification")
    def test_approve_payment_updates_order_and_generates_invoice(self, mocked_email):
        self._login_as("customer", "Customer")
        self.client.post(
            "/orders/1/upload-payment-proof",
            data={"payment_proof": (io.BytesIO(b"proof"), "proof.png")},
            content_type="multipart/form-data",
        )

        self._login_as("admin", "Admin")
        response = self.client.put("/admin/orders/1/approve-payment", json={})
        self.assertEqual(response.status_code, 200)

        conn = sqlite3.connect(sales_app.DATABASE_PATH)
        row = conn.execute(
            "SELECT payment_status, order_status, invoice_url, payment_verified_at FROM orders WHERE id=1"
        ).fetchone()
        conn.close()

        self.assertEqual(row[0], "paid")
        self.assertEqual(row[1], "confirmed")
        self.assertTrue(row[2].endswith(".pdf"))
        self.assertIsNotNone(row[3])
        mocked_email.assert_called_once()

    @patch("app.send_email_notification")
    def test_reject_payment_rolls_back_inventory_and_cancels_order(self, mocked_email):
        self._login_as("customer", "Customer")
        self.client.post(
            "/orders/1/upload-payment-proof",
            data={"payment_proof": (io.BytesIO(b"proof"), "proof.png")},
            content_type="multipart/form-data",
        )

        self._login_as("admin", "Admin")
        response = self.client.put("/admin/orders/1/reject-payment", json={"reason": "Blurry transfer slip"})
        self.assertEqual(response.status_code, 200)

        conn = sqlite3.connect(sales_app.DATABASE_PATH)
        order_row = conn.execute(
            "SELECT payment_status, order_status, cancellation_reason FROM orders WHERE id=1"
        ).fetchone()
        stock_row = conn.execute("SELECT stock FROM products WHERE id=1").fetchone()
        conn.close()

        self.assertEqual(order_row[0], "failed")
        self.assertEqual(order_row[1], "cancelled")
        self.assertEqual(order_row[2], "Blurry transfer slip")
        self.assertEqual(stock_row[0], 10)
        mocked_email.assert_called_once()

    def test_cannot_process_payment_twice(self):
        self._login_as("customer", "Customer")
        self.client.post(
            "/orders/1/upload-payment-proof",
            data={"payment_proof": (io.BytesIO(b"proof"), "proof.png")},
            content_type="multipart/form-data",
        )

        self._login_as("admin", "Admin")
        first = self.client.put("/admin/orders/1/approve-payment", json={})
        second = self.client.put("/admin/orders/1/approve-payment", json={})

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 409)


if __name__ == "__main__":
    unittest.main()