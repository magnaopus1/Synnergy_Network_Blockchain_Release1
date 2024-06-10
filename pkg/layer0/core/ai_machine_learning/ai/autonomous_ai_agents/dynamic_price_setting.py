class DynamicPriceSetter:
    def __init__(self, product_id: str, initial_price: float):
        self.product_id = product_id
        self.current_price = initial_price

    def adjust_price(self, market_demand: int, competitor_prices: dict, user_preferences: dict) -> float:
        """
        Adjusts the product price based on market demand, competitor prices, and user preferences.
        
        Args:
            market_demand (int): Current market demand for the product.
            competitor_prices (dict): Dictionary containing competitor prices for the product.
            user_preferences (dict): Dictionary containing user preferences for the product.
        
        Returns:
            float: The adjusted product price.
        """
        # Placeholder logic for adjusting the product price
        # Example: Price adjustment based on weighted average of market demand, competitor prices, and user preferences
        adjusted_price = self.current_price + 0.1 * market_demand - 0.05 * competitor_prices["average"] + \
                         0.05 * user_preferences.get("price_sensitivity", 0)

        # Ensure the price is within a reasonable range
        adjusted_price = max(adjusted_price, 0.01)  # Minimum price
        adjusted_price = min(adjusted_price, 1000.0)  # Maximum price

        self.current_price = adjusted_price
        return adjusted_price

    def update_price(self, new_price: float):
        """
        Updates the current price of the product.
        
        Args:
            new_price (float): The new price of the product.
        """
        self.current_price = new_price


def main():
    # Example usage
    product_id = "ABC123"
    initial_price = 50.0
    dynamic_price_setter = DynamicPriceSetter(product_id, initial_price)

    # Example market demand, competitor prices, and user preferences
    market_demand = 1000
    competitor_prices = {"average": 45.0, "best_offer": 40.0}
    user_preferences = {"price_sensitivity": 0.03}

    # Adjust the price based on market demand, competitor prices, and user preferences
    adjusted_price = dynamic_price_setter.adjust_price(market_demand, competitor_prices, user_preferences)
    print("Adjusted price:", adjusted_price)

    # Update the price to a new value
    dynamic_price_setter.update_price(adjusted_price * 1.1)
    print("Updated price:", dynamic_price_setter.current_price)


if __name__ == "__main__":
    main()
