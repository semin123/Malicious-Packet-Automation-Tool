// tab 이동
$(document).on("click", ".con .menu div", function() {
	var numberIndex = $(this).index();

	if (!$(this).is("active")) {
		$(".con .menu div").removeClass("active");
		$(".con ul li").removeClass("active");

		$(this).addClass("active");

		$(".con ul").find("li:eq(" + numberIndex + ")").addClass("active");

		var listItemHeight = $(".con ul")
			.find("li:eq(" + numberIndex + ")")
			.innerHeight();
		$(".con ul").height(listItemHeight + "px");
	}
});

// vt-tab 이동
$(document).on("click", ".vt-tabs div", function() {
	var tab_id = $(this).attr('data-tab');

	$(".vt-tabs div").removeClass("vt-active");
	$(".tab-content").removeClass("vt-active");

	$(this).addClass("vt-active");
	$("#"+tab_id).addClass('vt-active');
});