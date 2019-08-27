from ..mesh import *


class Scalar:
	__slots__ = "multiplier", "decimal_exponent", "binary_exponent"

	def __init__(self, multiplier: int, decimal_exponent: int, binary_exponent: int) -> None:
		self.multiplier = multiplier
		self.decimal_exponent = decimal_exponent
		self.binary_exponent = binary_exponent

	def calc(self, c: int) -> int:
		return c * self.multiplier * 10**self.decimal_exponent * 2**self.binary_exponent


class SensorDescriptor:
	PropertyID = NewType("PropertyID", int)
	__slots__ = ('property_id', 'positive_tolerance', 'negative_tolerance', 'sample_function', 'measurement_period'
																							   'update_interval')

	def __init__(self, property_id: PropertyID, positive_tolerance: int, negative_tolerance: int,
				 sample_function: int,
				 measurement_period: int, update_interval: int):
		self.property_id = property_id
		self.positive_tolerance = positive_tolerance
		self.negative_tolerance = negative_tolerance
		self.sample_function = sample_function
		self.measurement_period = measurement_period
		self.update_interval = update_interval
