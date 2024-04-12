objects=(
  '{"name":"John", "age":30, "city":"New York"}'
  '{"name":"Alice", "age":25, "city":"London"}'
)

# Loop through object array
for object in "${objects[@]}"; do
  name=$(jq -r '.name' <<< "$object")
  age=$(jq -r '.age' <<< "$object")
  city=$(jq -r '.city' <<< "$object")

  echo "Name: $name"
  echo "Age: $age"
  echo "City: $city"
  echo
done
