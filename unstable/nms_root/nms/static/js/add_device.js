function loadDropDownItems()
{
	var xmlhttp;
	if (window.XMLHttpRequest)
	{
		// IE7+, Firefox, Chrome, Opera, Safari
		xmlhttp = new XMLHttpRequest();
	}
	else
	{
		// IE6, IE5
		xmlhttp = new ActiveXObject("Microsoft.XMLHTTP");
	}
	xmlhttp.onreadystatechange = function()
	{
		if (xmlhttp.readyState == 4 && xmlhttp.status == 200)
		{
			var ret = xmlhttp.responseText.split('|');
			if (ret.length == 0)
			{
				return;
			}
			if (ret[0] == "<Error>")
			{
				document.getElementById("selectModel").disabled = true;
				return;
			}

			var selectElement = document.getElementById("selectModel");
			selectElement.innerHTML = "";
			for (var i = 0; i < ret.length; i++)
			{
				var option = document.createElement("option");
				option.text = ret[i];
				try
				{
					selectElement.add(option, null);
				}
				catch (e)
				{
					selectElement.add(option, selectElement.options[null]);
				}
			}
			document.getElementById("selectModel").disabled = false;
		}
	}
	var selectType = document.getElementById("selectType");
	var selectVendor = document.getElementById("selectVendor");
	var dtype = selectType.options[selectType.selectedIndex].text;
	var dvendor = selectVendor.options[selectVendor.selectedIndex].text;

	var args = "?type=models&q=".concat(dtype, "|", dvendor);
	xmlhttp.open("GET", "{% url 'nms:query' %}".concat(args), true);
	xmlhttp.send();
}